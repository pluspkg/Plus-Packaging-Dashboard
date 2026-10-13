// Plus Transport Dashboard API, served same-origin at dashboards.pluspkg.com/api/transport/*
//
// Identity comes from Cloudflare Access: every request reaching this function carries a signed
// Cf-Access-Jwt-Assertion header, which is verified here. Roles live in transport.app_users.
//
// Pages environment variables (Settings > Variables and Secrets):
//   TRANSPORT_DATABASE_URL  secret  Neon connection string (pooled)
//   ACCESS_TEAM_DOMAIN      text    e.g. yourteam.cloudflareaccess.com
//   ACCESS_AUD              text    Application Audience (AUD) tag of the dashboards Access application
import { neon } from '../../_lib/neon-serverless.mjs';

const ALLOWED_DOMAIN = '@pluspkg.com';
const MAX_IMPORT_BYTES = 6 * 1024 * 1024;

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
const fail = (status, error, detail) => json({ error, ...(detail ? { detail } : {}) }, status);

// ---------------------------------------------------------------------------
// Cloudflare Access token check
// ---------------------------------------------------------------------------

// Access's signing keys rotate rarely; keep them for ten minutes per isolate.
let accessKeyCache = { team: null, at: 0, keys: [] };

async function accessKeys(team, force = false) {
  const fresh = Date.now() - accessKeyCache.at < 10 * 60 * 1000;
  if (!force && fresh && accessKeyCache.team === team) return accessKeyCache.keys;
  const res = await fetch(`https://${team}/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error(`Could not load Access signing keys (${res.status})`);
  const body = await res.json();
  accessKeyCache = { team, at: Date.now(), keys: body.keys || [] };
  return accessKeyCache.keys;
}

function base64UrlBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const base64UrlJson = (s) => JSON.parse(new TextDecoder().decode(base64UrlBytes(s)));

export async function verifyAccessToken(token, env) {
  const team = String(env.ACCESS_TEAM_DOMAIN || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('Malformed Access token');
  const header = base64UrlJson(parts[0]);
  const claims = base64UrlJson(parts[1]);
  if (header.alg !== 'RS256') throw new Error(`Unexpected token algorithm ${header.alg}`);

  let jwk = (await accessKeys(team)).find((k) => k.kid === header.kid);
  if (!jwk) jwk = (await accessKeys(team, true)).find((k) => k.kid === header.kid);   // keys rotated
  if (!jwk) throw new Error('Access token signed with an unknown key');

  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const signed = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, base64UrlBytes(parts[2]), signed);
  if (!valid) throw new Error('Access token signature is not valid');

  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp === 'number' && claims.exp < now) throw new Error('Access token has expired');
  if (typeof claims.nbf === 'number' && claims.nbf > now + 60) throw new Error('Access token is not valid yet');
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(env.ACCESS_AUD)) throw new Error('Access token is for a different application (check ACCESS_AUD)');
  if (claims.iss !== `https://${team}`) throw new Error('Access token issuer does not match ACCESS_TEAM_DOMAIN');
  return claims;
}

function missingSettings(env) {
  return ['TRANSPORT_DATABASE_URL', 'ACCESS_TEAM_DOMAIN', 'ACCESS_AUD'].filter((k) => !env[k]);
}

async function identify(request, env, sql) {
  const token = request.headers.get('cf-access-jwt-assertion');
  if (!token) return { error: fail(401, 'This request did not come through Cloudflare Access') };
  let claims;
  try {
    claims = await verifyAccessToken(token, env);
  } catch (e) {
    return { error: fail(401, 'Cloudflare Access sign-in could not be verified', e.message) };
  }
  const email = String(claims.email || '').toLowerCase();
  if (!email.endsWith(ALLOWED_DOMAIN)) return { error: fail(403, 'Only Plus Packaging accounts can use this dashboard') };
  const rows = await sql.query('select role, active, display_name, pay_access, courier_access from transport.app_users where email = $1', [email]);
  const user = rows[0];
  const role = user && user.active && user.role === 'admin' ? 'admin' : 'standard';
  const active = Boolean(user && user.active);
  return { user: { email, role, name: (user && user.display_name) || null,
                   pay: active && Boolean(user.pay_access), couriers: active && (role === 'admin' || Boolean(user.courier_access)) } };
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

const isDate = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);

async function validation(url, sql) {
  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');
  if (!isDate(from) || !isDate(to)) return fail(400, 'Give from and to as YYYY-MM-DD');

  const [vehicles, totals, flags, coverage] = await Promise.all([
    sql.query(`
      select vehicle, maxoptra_name, vehicle_type, bool_or(in_kpi) as in_kpi,
             (count(*) filter (where operated))::int         as days,
             sum(drop_order_lines)::int                       as drop_order_lines,
             sum(completed_drop_order_lines)::int             as completed_order_lines,
             sum(completed_drops)::int                        as completed_drops,
             sum(failed_drops)::int                           as failed_drops,
             sum(second_runs)::int                            as second_runs,
             sum(runs_rebuilt)::int                           as runs_rebuilt
      from transport.v_vehicle_day
      where run_date between $1 and $2
      group by vehicle, maxoptra_name, vehicle_type
      order by case vehicle_type when 'full_time_van' then 1 when 'truck' then 2 when 'support' then 3 else 4 end, vehicle`,
      [from, to]),
    sql.query(`
      select count(*)::int as van_days,
             sum(drop_order_lines)::int as drop_order_lines,
             sum(completed_drop_order_lines)::int as completed_order_lines,
             sum(completed_drops)::int as completed_drops
      from transport.v_vehicle_day
      where run_date between $1 and $2 and vehicle_type = 'full_time_van' and in_kpi and operated`,
      [from, to]),
    sql.query(`
      select rule, count(*)::int as count, min(detail) as example
      from transport.anomaly_flags where run_date between $1 and $2
      group by rule order by count(*) desc`,
      [from, to]),
    sql.query(`
      select count(distinct run_date)::int as days_with_data,
             (select count(*)::int from generate_series($1::date, $2::date, interval '1 day') d
              where extract(isodow from d) < 6
                and not exists (select 1 from transport.runs r where r.run_date = d::date and r.removed_at is null)) as weekdays_without_data
      from transport.runs where run_date between $1 and $2 and removed_at is null`,
      [from, to]),
  ]);
  return json({ from, to, vehicles, full_time_vans: totals[0], flags, coverage: coverage[0] });
}

async function status(sql) {
  const [range, recent] = await Promise.all([
    sql.query(`select min(run_date)::text as first_date, max(run_date)::text as last_date, count(*)::int as runs,
                      (select count(*)::int from transport.orders where removed_at is null) as orders
               from transport.runs where removed_at is null`),
    sql.query(`select source, status, started_at, finished_at, date_from::text, date_to::text, runs_upserted, orders_upserted,
                      message, triggered_by
               from transport.sync_log order by started_at desc limit 10`),
  ]);
  return json({ data: range[0], recent });
}

// ---------------------------------------------------------------------------
// Live: today's fleet, worked out from the latest sync
// ---------------------------------------------------------------------------

const londonClock = new Intl.DateTimeFormat('en-GB', {
  timeZone: 'Europe/London', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', weekday: 'short',
});
export function londonNow(date = new Date()) {
  const p = Object.fromEntries(londonClock.formatToParts(date).map((x) => [x.type, x.value]));
  return { date: `${p.year}-${p.month}-${p.day}`, stamp: `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`,
           minutes: Number(p.hour) * 60 + Number(p.minute), weekday: p.weekday };
}
const toMs = (t) => (t ? Date.parse(t.replace(' ', 'T') + 'Z') : null);          // wall-clock arithmetic only
const minutesBetween = (a, b) => (a && b ? Math.round((toMs(b) - toMs(a)) / 60000) : null);
const addMinutes = (t, m) => new Date(toMs(t) + m * 60000).toISOString().slice(0, 19).replace('T', ' ');
const clock = (t) => (t ? t.slice(11, 16) : null);

const LIVE_RUNS = `
  with o as (
    select o.run_key, o.stop_key, o.task, o.sequence, o.client_name, o.order_status, o.completion_status, o.fail_reason,
           o.planned_arrival, o.planned_departure, o.eta, o.etd,
           coalesce(o.gps_arrival, o.reported_arrival) as act_arr,
           coalesce(o.gps_departure, o.reported_departure) as act_dep,
           coalesce(o.order_status in ('CLOSED', 'FAILED') or o.completion_status in ('FULLY_DELIVERED', 'PARTIALLY_DELIVERED'), false) as done
    from transport.orders o
    where o.run_date = $1 and o.removed_at is null
  ), s as (
    select run_key, stop_key, coalesce(bool_or(task = 'DROP'), false) as is_drop, bool_and(done) as done,
      coalesce(bool_or(completion_status in ('FULLY_DELIVERED', 'PARTIALLY_DELIVERED')), false) as completed,
      coalesce(bool_or(order_status = 'FAILED' or fail_reason is not null), false)
        and not coalesce(bool_or(completion_status in ('FULLY_DELIVERED', 'PARTIALLY_DELIVERED')), false) as failed,
      min(sequence) as seq, min(planned_arrival) as planned_arrival, max(planned_departure) as planned_departure,
      min(act_arr) as act_arr, max(act_dep) as act_dep, min(eta) as eta, max(etd) as etd, max(client_name) as client
    from o group by run_key, stop_key
  )
  select r.run_key, r.run_number, r.vehicle_id, coalesce(v.display_name, v.maxoptra_name) as vehicle, v.vehicle_type,
    (v.kpi_included and (v.kpi_from is null or r.run_date >= v.kpi_from) and (v.kpi_to is null or r.run_date <= v.kpi_to)) as in_kpi,
    d.name as driver,
    r.planned_departure::text, r.actual_departure::text, r.planned_end::text, r.actual_end::text,
    r.planned_distance::float8 as planned_miles, r.actual_distance::float8 as actual_miles, r.run_cost::float8 as est_cost,
    count(s.stop_key)::int as stops,
    (count(s.stop_key) filter (where not s.done))::int as stops_open,
    (count(s.stop_key) filter (where s.is_drop))::int as planned_drops,
    (count(s.stop_key) filter (where s.is_drop and s.completed))::int as completed_drops,
    (count(s.stop_key) filter (where s.is_drop and s.failed))::int as failed_drops,
    (count(s.stop_key) filter (where s.is_drop and not s.done))::int as open_drops,
    (count(s.stop_key) filter (where s.is_drop and s.done and not s.completed and not s.failed))::int as closed_no_items,
    min(s.act_arr)::text as first_arrival,
    (max(s.act_dep) filter (where s.done))::text as last_departure,
    ((array_agg(s.planned_arrival order by s.seq desc nulls last) filter (where s.done and s.act_arr is not null))[1])::text as last_done_planned,
    ((array_agg(s.act_arr order by s.seq desc nulls last) filter (where s.done and s.act_arr is not null))[1])::text as last_done_actual,
    ((array_agg(s.planned_arrival order by s.seq nulls last) filter (where not s.done))[1])::text as next_planned,
    ((array_agg(s.eta order by s.seq nulls last) filter (where not s.done))[1])::text as next_eta,
    (array_agg(s.client order by s.seq nulls last) filter (where not s.done))[1] as next_client,
    ((array_agg(s.planned_departure order by s.seq desc nulls last))[1])::text as last_stop_planned_departure,
    ((array_agg(s.planned_arrival order by s.seq desc nulls last))[1])::text as last_stop_planned_arrival,
    ((array_agg(s.etd order by s.seq desc nulls last) filter (where not s.done))[1])::text as final_etd,
    ((array_agg(s.eta order by s.seq desc nulls last) filter (where not s.done))[1])::text as final_eta
  from transport.runs r
  join transport.vehicles v on v.id = r.vehicle_id
  left join transport.drivers d on d.id = r.driver_id
  left join s on s.run_key = r.run_key
  where r.run_date = $1 and r.removed_at is null
  group by r.run_key, r.run_number, r.vehicle_id, v.display_name, v.maxoptra_name, v.vehicle_type, v.kpi_included,
           v.kpi_from, v.kpi_to, r.run_date, d.name, r.planned_departure, r.actual_departure, r.planned_end, r.actual_end,
           r.planned_distance, r.actual_distance, r.run_cost
  order by 4, r.run_number`;

// Every stop (customer visit) on a day, for the drill-downs. Several orders at one stop are one row.
const STOPS = `
  select o.run_key, o.stop_key,
    min(o.sequence) as seq,
    max(o.client_name) as client, max(o.location_name) as location, max(o.location_postcode) as postcode,
    bool_or(o.task = 'DROP') as is_drop,
    count(*)::int as orders, string_agg(o.order_ref, ', ' order by o.order_ref) as order_refs,
    min(o.planned_arrival)::text as planned_arrival,
    min(o.eta)::text as eta,
    min(coalesce(o.gps_arrival, o.reported_arrival))::text as arrived,
    max(coalesce(o.gps_departure, o.reported_departure))::text as departed,
    min(o.window_start)::text as window_start, max(o.window_end)::text as window_end,
    coalesce(bool_or(o.completion_status in ('FULLY_DELIVERED', 'PARTIALLY_DELIVERED')), false) as completed,
    coalesce(bool_or(o.order_status = 'FAILED' or o.fail_reason is not null), false) as any_failed,
    bool_and(coalesce(o.order_status in ('CLOSED', 'FAILED') or o.completion_status in ('FULLY_DELIVERED', 'PARTIALLY_DELIVERED'), false)) as done,
    string_agg(distinct o.fail_reason, '; ') as fail_reason,
    string_agg(distinct o.fail_comment, '; ') as fail_comment
  from transport.orders o
  where o.run_date = $1 and o.removed_at is null
  group by o.run_key, o.stop_key
  order by o.run_key, 3`;

// One stop, ready to show: times as HH:MM, minutes on site, arrival against plan and the customer's window.
export function mapStop(s, now) {
  const onSite = s.arrived && s.departed ? minutesBetween(s.arrived, s.departed) : null;
  const windowStart = s.window_start ? s.window_start.slice(11, 16) : null;
  const windowEnd = s.window_end ? s.window_end.slice(11, 16) : null;
  const anyTime = windowStart === '00:00' && (windowEnd === '23:59' || windowEnd === '00:00');
  const arrivedClock = clock(s.arrived);
  // Arriving before the customer's window opens and arriving after it closes are different problems.
  const windowFlag = !arrivedClock || anyTime ? null
    : windowStart && arrivedClock < windowStart ? 'before'
    : windowEnd && windowEnd !== '00:00' && arrivedClock > windowEnd ? 'after' : null;
  let status;
  if (s.completed) status = s.is_drop ? 'delivered' : 'collected';
  else if (s.any_failed) status = 'failed';
  else if (s.done) status = 'closed_no_items';
  else status = 'open';
  const attr = (s.attributes || '').match(/Sell To Customer No:\s*([A-Za-z0-9]+)/);
  return {
    seq: s.seq, client: s.client, location: s.location, postcode: s.postcode,
    type: s.is_drop ? 'drop' : 'collection', orders: s.orders, order_refs: s.order_refs,
    window: windowStart && windowEnd && !anyTime ? `${windowStart}–${windowEnd}` : null,
    planned: clock(s.planned_arrival), eta: status === 'open' ? clock(s.eta) : null,
    arrived: arrivedClock, departed: clock(s.departed),
    on_site: onSite !== null && onSite >= 0 && onSite < 600 ? onSite : null,
    vs_plan: s.arrived && s.planned_arrival ? minutesBetween(s.arrived, s.planned_arrival) : null,
    window_flag: windowFlag,
    status, fail_reason: s.fail_reason || null, fail_comment: s.fail_comment || null,
    customer_no: attr ? attr[1] : null,
    ...(s.date ? { date: s.date, vehicle: s.vehicle, driver: s.driver, run_number: s.run_number } : {}),
  };
}

// Thresholds for live status, in minutes.
const LATE_AFTER = 10;          // nothing reported this long after the planned departure: Late
const NO_DATA_AFTER = 60;       // ...and after this long: No data (the driver app probably isn't in use)
const BACK_AFTER_ESTIMATE = 30; // returning, and this long past the estimated return: treated as back

export function runState(run, now) {
  // MaxOptra sometimes records a return earlier than the run's last job (seen on second runs): ignore it.
  const actualEnd = run.actual_end && (!run.last_departure || run.actual_end >= run.last_departure) ? run.actual_end : null;
  const leg = minutesBetween(run.last_stop_planned_departure, run.planned_end);
  const estimatedReturn = run.stops > 0 && run.stops_open === 0 && run.last_departure && leg !== null && leg >= 0 && leg <= 300
    ? addMinutes(run.last_departure, leg) : null;
  const started = Boolean(run.actual_departure || run.first_arrival || run.stops_open < run.stops);
  let status;
  let variance = null;                           // minutes: positive = ahead of plan
  if (actualEnd) status = 'back';
  else if (run.stops > 0 && run.stops_open === 0) {
    status = estimatedReturn && minutesBetween(estimatedReturn, now) > BACK_AFTER_ESTIMATE ? 'back_estimated' : 'returning';
  } else if (!started) {
    const late = run.planned_departure ? minutesBetween(run.planned_departure, now) : null;
    if (late === null || late < LATE_AFTER) status = 'not_departed';
    else if (late < NO_DATA_AFTER) { status = 'late'; variance = -late; }
    else status = 'no_data';
  } else status = 'out';
  // Left but nothing reported since, and well past the planned return: the driver app isn't being used
  if (status === 'out' && run.stops_open === run.stops && run.planned_end && minutesBetween(run.planned_end, now) > NO_DATA_AFTER) status = 'no_data';
  if (status === 'out') {
    // still out: the next stop's ETA against its planned arrival, else the last stop reached
    if (run.next_eta && run.next_planned) variance = minutesBetween(run.next_eta, run.next_planned);
    else if (run.last_done_actual && run.last_done_planned) variance = minutesBetween(run.last_done_actual, run.last_done_planned);
  } else if (['returning', 'back', 'back_estimated'].includes(status) && run.planned_end) {
    // finished: back at Plus (actual, else estimated) against the planned return
    const back = actualEnd || estimatedReturn;
    if (back) variance = minutesBetween(back, run.planned_end);
  }
  // When it should be back at Plus. Out: MaxOptra's ETA for the final stop, plus the planned time there and the
  // planned drive home; without ETAs, the plan moved by how far ahead or behind it is. Returning: the estimate.
  let expected = null;
  const legOk = leg !== null && leg >= 0 && leg <= 300;
  if (status === 'out') {
    const service = minutesBetween(run.last_stop_planned_arrival, run.last_stop_planned_departure);
    if (run.final_etd && legOk) expected = addMinutes(run.final_etd, leg);
    else if (run.final_eta && legOk) expected = addMinutes(run.final_eta, (service !== null && service >= 0 && service <= 240 ? service : 0) + leg);
    else if (variance !== null && run.planned_end) expected = addMinutes(run.planned_end, -variance);
  } else if (status === 'returning') expected = estimatedReturn;
  else if (status === 'late' && run.planned_end && variance !== null) expected = addMinutes(run.planned_end, -variance);
  return { status, variance, estimated_return: estimatedReturn, actual_end: actualEnd, expected_return: expected,
           expected_vs_plan: expected && run.planned_end ? minutesBetween(run.planned_end, expected) : null };
}

const ACTIVE = ['out', 'returning', 'late', 'no_data'];

export function buildLive(runs, now) {
  const vehicles = new Map();
  for (const r of runs) {
    const state = runState(r, now);
    const run = { run_key: r.run_key, run_number: r.run_number, driver: r.driver, status: state.status, variance: state.variance,
      planned_drops: r.planned_drops, completed_drops: r.completed_drops, failed_drops: r.failed_drops,
      open_drops: r.open_drops, closed_no_items: r.closed_no_items,
      planned_departure: clock(r.planned_departure), actual_departure: clock(r.actual_departure),
      planned_return: clock(r.planned_end), actual_return: clock(state.actual_end),
      estimated_return: clock(state.estimated_return), last_job: clock(r.last_departure),
      expected_return: clock(state.expected_return), expected_late_by: state.expected_vs_plan,
      next_client: r.next_client, next_due: clock(r.next_eta || r.next_planned),
      planned_miles: r.planned_miles, actual_miles: r.actual_miles, est_cost: r.est_cost };
    if (!vehicles.has(r.vehicle_id)) vehicles.set(r.vehicle_id, { vehicle: r.vehicle, vehicle_type: r.vehicle_type, in_kpi: r.in_kpi, runs: [] });
    vehicles.get(r.vehicle_id).runs.push(run);
  }
  const list = [...vehicles.values()].map((v) => {
    v.runs.sort((a, b) => a.run_number - b.run_number);
    const current = v.runs.filter((r) => ACTIVE.includes(r.status)).sort((a, b) => ACTIVE.indexOf(a.status) - ACTIVE.indexOf(b.status) || a.run_number - b.run_number)[0]
      || v.runs.find((r) => r.status === 'not_departed')
      || v.runs[v.runs.length - 1];
    const sum = (k) => v.runs.reduce((t, r) => t + (r[k] || 0), 0);
    return { ...v, current, driver: current.driver,
      drivers: [...new Set(v.runs.map((r) => r.driver).filter(Boolean))],
      run_count: v.runs.length,
      runs_finished: v.runs.filter((r) => ['back', 'back_estimated', 'returning'].includes(r.status)).length,
      planned_drops: sum('planned_drops'), completed_drops: sum('completed_drops'), failed_drops: sum('failed_drops'),
      open_drops: sum('open_drops'), closed_no_items: sum('closed_no_items'),
      planned_miles: sum('planned_miles'), est_cost: sum('est_cost'),
      actual_miles: v.runs.some((r) => r.actual_miles !== null) ? sum('actual_miles') : null,
      runs_with_actual_miles: v.runs.filter((r) => r.actual_miles !== null).length,
      last_job: v.runs.map((r) => r.last_job).filter(Boolean).sort().pop() || null,
      second_runs: v.runs.filter((r) => r.run_number >= 2).length };
  });
  const vans = list.filter((v) => v.vehicle_type === 'full_time_van' && v.in_kpi && v.planned_drops > 0);
  const sum = (arr, k) => arr.reduce((t, x) => t + (x[k] || 0), 0);
  return {
    vehicles: list,
    headline: {
      planned_drops: sum(list, 'planned_drops'), completed_drops: sum(list, 'completed_drops'),
      failed_drops: sum(list, 'failed_drops'), open_drops: sum(list, 'open_drops'),
      van_count: vans.length, van_completed: sum(vans, 'completed_drops'),
      vans_active: list.filter((v) => ['full_time_van', 'support'].includes(v.vehicle_type)).length,
      trucks_active: list.filter((v) => v.vehicle_type === 'truck').length,
      vehicles_out: list.filter((v) => ['out', 'returning', 'late', 'no_data'].includes(v.current.status)).length,
      vehicles_returning: list.filter((v) => v.current.status === 'returning').length,
      runs: sum(list, 'run_count'), second_runs: sum(list, 'second_runs'),
      planned_miles: sum(list, 'planned_miles'), est_cost: sum(list, 'est_cost'),
      actual_miles: sum(list, 'actual_miles'), runs_with_actual_miles: sum(list, 'runs_with_actual_miles'),
    },
  };
}

// Plus's own cost of each run (transport.run_costs): driver pay, lease and fuel. Everyone sees the running cost
// (lease or hire, and fuel). Driver pay, and any total that includes it, goes only to people with pay access:
// a van's daily cost would otherwise reveal its driver's pay.
const RUN_COSTS = `
  select run_key, driver_cost::float8, lease_cost::float8, fuel_cost::float8, fuel_miles::float8, fuel_on_actual,
         driver_rate_missing, lease_missing, mpg_missing, fuel_price_missing
  from transport.run_costs($1::date, $2::date)`;

function costOf(c, withPay) {
  if (!c) return null;
  const parts = withPay ? [c.driver_cost, c.lease_cost, c.fuel_cost] : [c.lease_cost, c.fuel_cost];
  const missing = [withPay && c.driver_rate_missing && 'driver pay', c.lease_missing && 'lease', c.mpg_missing && 'MPG', c.fuel_price_missing && 'fuel price'].filter(Boolean);
  return { total: parts.some((x) => x !== null) ? parts.reduce((t, x) => t + (x || 0), 0) : null,
           ...(withPay ? { driver: c.driver_cost } : {}), lease: c.lease_cost, fuel: c.fuel_cost, fuel_miles: c.fuel_miles,
           fuel_on_actual: c.fuel_on_actual, includes_pay: Boolean(withPay), missing };
}
function addCosts(a, b) {
  if (!b) return a;
  if (!a) return { ...b, missing: [...b.missing] };
  const add = (x, y) => (x === null && y === null ? null : (x || 0) + (y || 0));
  const out = { total: add(a.total, b.total), lease: add(a.lease, b.lease), fuel: add(a.fuel, b.fuel),
                fuel_miles: add(a.fuel_miles, b.fuel_miles), fuel_on_actual: a.fuel_on_actual && b.fuel_on_actual,
                includes_pay: a.includes_pay, missing: [...new Set([...a.missing, ...b.missing])] };
  if ('driver' in a || 'driver' in b) out.driver = add(a.driver ?? null, b.driver ?? null);
  return out;
}

// A whole day: vehicles, their runs (with live status as at `stamp`) and every stop on each run.
async function dayData(sql, date, stamp, withPay) {
  const [runs, stops, costs] = await Promise.all([
    sql.query(LIVE_RUNS, [date]), sql.query(STOPS, [date]), sql.query(RUN_COSTS, [date, date]),
  ]);
  const built = buildLive(runs, stamp);
  const byRun = new Map();
  for (const st of stops) {
    if (!byRun.has(st.run_key)) byRun.set(st.run_key, []);
    byRun.get(st.run_key).push(mapStop(st, stamp));
  }
  const costBy = new Map(costs.map((c) => [c.run_key, costOf(c, withPay)]));
  for (const v of built.vehicles) {
    for (const r of v.runs) {
      r.stops = byRun.get(r.run_key) || [];
      r.cost = costBy.get(r.run_key) || null;
      v.cost = addCosts(v.cost || null, r.cost);
    }
    built.headline.cost = addCosts(built.headline.cost || null, v.cost);
  }
  // MaxOptra's own run cost is built from an hourly rate per driver, so it's treated like pay
  if (!withPay) {
    for (const v of built.vehicles) { delete v.est_cost; for (const r of v.runs) delete r.est_cost; }
    delete built.headline.est_cost;
  }
  return built;
}

async function day(url, sql, user) {
  const date = url.searchParams.get('date');
  if (!isDate(date)) return fail(400, 'Give date as YYYY-MM-DD');
  const now = londonNow();
  const stamp = date === now.date ? now.stamp : `${date} 23:59:59`;
  const [built, target] = await Promise.all([
    dayData(sql, date, stamp, user.pay),
    sql.query(`select transport.target_on('van_drops_per_day', $1::date) as target`, [date]),
  ]);
  return json({ date, live: date === now.date, target: target[0] && target[0].target !== null ? Number(target[0].target) : null, ...built });
}

// One customer's visits over a date range (the drill-down from any customer name).
async function customer(url, sql) {
  const name = url.searchParams.get('name');
  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');
  if (!name || !isDate(from) || !isDate(to)) return fail(400, 'Give name, from and to');
  const rows = await sql.query(`
    select o.run_date::text as date, r.run_number, coalesce(v.display_name, v.maxoptra_name) as vehicle, d.name as driver,
      o.run_key, o.stop_key, min(o.sequence) as seq,
      max(o.client_name) as client, max(o.location_name) as location, max(o.location_postcode) as postcode,
      bool_or(o.task = 'DROP') as is_drop, count(*)::int as orders, string_agg(o.order_ref, ', ' order by o.order_ref) as order_refs,
      min(o.planned_arrival)::text as planned_arrival, min(o.eta)::text as eta,
      min(coalesce(o.gps_arrival, o.reported_arrival))::text as arrived,
      max(coalesce(o.gps_departure, o.reported_departure))::text as departed,
      min(o.window_start)::text as window_start, max(o.window_end)::text as window_end,
      coalesce(bool_or(o.completion_status in ('FULLY_DELIVERED', 'PARTIALLY_DELIVERED')), false) as completed,
      coalesce(bool_or(o.order_status = 'FAILED' or o.fail_reason is not null), false) as any_failed,
      bool_and(coalesce(o.order_status in ('CLOSED', 'FAILED') or o.completion_status in ('FULLY_DELIVERED', 'PARTIALLY_DELIVERED'), false)) as done,
      string_agg(distinct o.fail_reason, '; ') as fail_reason, string_agg(distinct o.fail_comment, '; ') as fail_comment,
      max(o.attributes) as attributes, max(o.instructions) as instructions
    from transport.orders o
    join transport.runs r using (run_key)
    join transport.vehicles v on v.id = r.vehicle_id
    left join transport.drivers d on d.id = r.driver_id
    where o.client_name = $1 and o.run_date between $2 and $3 and o.removed_at is null and r.removed_at is null
    group by o.run_date, r.run_number, v.display_name, v.maxoptra_name, d.name, o.run_key, o.stop_key
    order by o.run_date desc, min(o.sequence)
    limit 500`, [name, from, to]);
  const now = londonNow().stamp;
  const visits = rows.map((r) => mapStop(r, now));
  const instructions = rows.map((r) => r.instructions).find((t) => t && t.trim()) || null;
  return json({ name, from, to, visits, instructions: instructions ? instructions.replace(/\s+/g, ' ').trim().slice(0, 600) : null,
                customer_no: visits.map((v) => v.customer_no).find(Boolean) || null });
}

async function live(sql, user) {
  const now = londonNow();
  const [built, sync, events, target] = await Promise.all([
    dayData(sql, now.date, now.stamp, user.pay),
    // Today's freshness only: history being pulled in the background logs past dates and must not count.
    sql.query(`select
        (select started_at from transport.sync_log where source = 'report_api' and status = 'ok'
           and date_from = $1::date order by id desc limit 1) as last_ok,
        (select started_at from transport.sync_log where source = 'report_api' and status = 'error'
           and date_from <= $1::date and date_to >= $1::date order by id desc limit 1) as last_error_at,
        (select message from transport.sync_log where source = 'report_api' and status = 'error'
           and date_from <= $1::date and date_to >= $1::date order by id desc limit 1) as last_error`, [now.date]),
    sql.query(`select id, detail from transport.events where event_date = $1 and event_type = 'last_job_done'
               order by created_at desc, id desc limit 30`, [now.date]),
    sql.query(`select transport.target_on('van_drops_per_day', $1::date) as target`, [now.date]),
  ]);
  const s = sync[0] || {};
  const lastOk = s.last_ok ? londonNow(new Date(s.last_ok)) : null;
  const lastErr = s.last_error_at ? londonNow(new Date(s.last_error_at)) : null;
  // The sync runs every 5 minutes 06:00-17:00 and every 15 minutes 05:30-06:00 and 17:00-19:30 on weekdays,
  // so allow three missed runs before warning.
  const weekday = !['Sat', 'Sun'].includes(now.weekday);
  const m = now.minutes;
  const staleAfter = !weekday ? null
    : (m >= 6 * 60 && m < 17 * 60) ? 15
    : ((m >= 6 * 60 - 15 && m < 6 * 60) || (m >= 17 * 60 && m < 19 * 60 + 30)) ? 45 : null;
  const ageMin = s.last_ok ? Math.round((Date.now() - new Date(s.last_ok).getTime()) / 60000) : null;
  return json({
    date: now.date, now: now.stamp.slice(11, 16),
    sync: {
      last_ok: lastOk ? (lastOk.date === now.date ? lastOk.stamp.slice(11, 16) : lastOk.stamp.slice(0, 16)) : null,
      age_minutes: ageMin,
      stale: staleAfter !== null && (ageMin === null || ageMin > staleAfter),
      failing: Boolean(s.last_error_at && (!s.last_ok || new Date(s.last_error_at) > new Date(s.last_ok))),
      last_error: s.last_error || null, last_error_at: lastErr ? lastErr.stamp.slice(11, 16) : null,
    },
    target: target[0] && target[0].target !== null ? Number(target[0].target) : null,
    ...built,
    events: events.map((e) => {
      const t = (k) => (e.detail[k] ? String(e.detail[k]).replace('T', ' ') : null);
      const actual = t('actual_return') && t('last_job_at') && t('actual_return') < t('last_job_at') ? null : t('actual_return');
      return { id: Number(e.id), ...e.detail, last_job_at: clock(t('last_job_at')),
               estimated_return: clock(t('estimated_return')), actual_return: clock(actual) };
    }),
  });
}

// ---------------------------------------------------------------------------
// Period report: any date range (the page asks for rolling month, rolling quarter or custom dates)
// ---------------------------------------------------------------------------

async function report(url, sql, user) {
  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');
  if (!isDate(from) || !isDate(to) || from > to) return fail(400, 'Give from and to as YYYY-MM-DD, from before to');
  if ((Date.parse(to) - Date.parse(from)) / 86400000 > 400) return fail(400, 'Choose a range of 400 days or less');

  const [vehicles, drivers, failures, daily, missing, hours, vehicleDaily, costs] = await Promise.all([
    sql.query(`
      select vehicle, maxoptra_name, vehicle_type, hours_profile, bool_or(in_kpi) as in_kpi,
        (count(*) filter (where operated))::int as days,
        sum(planned_drops)::int as planned_drops, sum(completed_drops)::int as completed_drops,
        sum(failed_drops)::int as failed_drops, sum(runs)::int as runs, sum(second_runs)::int as second_runs,
        sum(second_run_completed_drops)::int as second_run_drops,
        round(sum(planned_miles), 1)::float8 as planned_miles,
        round(sum(actual_miles), 1)::float8 as actual_miles,
        round(sum(planned_miles) filter (where actual_miles is not null), 1)::float8 as planned_miles_tracked,
        (count(*) filter (where actual_miles is not null))::int as days_miles_tracked,
        round(avg(extract(epoch from (coalesce(actual_return, estimated_return) - first_actual_departure)) / 60)
              filter (where first_actual_departure is not null and coalesce(actual_return, estimated_return) > first_actual_departure))::int as avg_day_minutes,
        (count(*) filter (where first_actual_departure is not null and coalesce(actual_return, estimated_return) > first_actual_departure))::int as days_timed,
        round(avg(extract(epoch from coalesce(actual_return, estimated_return)::time) / 60)
              filter (where coalesce(actual_return, estimated_return) is not null))::int as avg_return_minute
      from transport.v_vehicle_day
      where run_date between $1 and $2
      group by vehicle, maxoptra_name, vehicle_type, hours_profile
      order by vehicle`, [from, to]),
    sql.query(`
      select s.driver_id, d.name as driver, (count(distinct s.run_date))::int as days, (count(distinct s.run_key))::int as runs,
        (count(*) filter (where s.completed))::int as completed_drops, (count(*) filter (where s.failed))::int as failed_drops,
        (count(distinct s.run_key) filter (where s.run_number >= 2))::int as second_runs,
        string_agg(distinct coalesce(v.display_name, v.maxoptra_name), ', ') as vehicles
      from transport.v_drop_stops s
      join transport.drivers d on d.id = s.driver_id
      join transport.vehicles v on v.id = s.vehicle_id
      where s.run_date between $1 and $2 and v.vehicle_type = 'full_time_van' and d.kpi_included
      group by s.driver_id, d.name`, [from, to]),
    sql.query(`
      select s.run_date::text as date, coalesce(v.display_name, v.maxoptra_name) as vehicle, d.name as driver,
             s.client_name, s.fail_reasons
      from transport.v_drop_stops s
      join transport.vehicles v on v.id = s.vehicle_id
      left join transport.drivers d on d.id = s.driver_id
      where s.run_date between $1 and $2 and s.failed
      order by s.run_date desc, vehicle limit 200`, [from, to]),
    sql.query(`
      select run_date::text as date,
        (sum(completed_drops) filter (where vehicle_type = 'full_time_van' and in_kpi and operated))::int as van_completed,
        (count(*) filter (where vehicle_type = 'full_time_van' and in_kpi and operated))::int as van_days,
        sum(completed_drops)::int as completed_drops, sum(planned_drops)::int as planned_drops,
        sum(failed_drops)::int as failed_drops, sum(second_runs)::int as second_runs,
        transport.target_on('van_drops_per_day', run_date)::float8 as target
      from transport.v_vehicle_day
      where run_date between $1 and $2
      group by run_date order by run_date`, [from, to]),
    sql.query(`
      select d::date::text as date from generate_series($1::date, $2::date, interval '1 day') d
      where extract(isodow from d) < 6
        and d::date < (now() at time zone 'Europe/London')::date
        and not exists (select 1 from transport.runs r where r.run_date = d::date and r.removed_at is null)
        -- a day MaxOptra was asked for and had nothing (a bank holiday) is not missing
        and not exists (select 1 from transport.sync_log l where l.status = 'ok' and l.date_from <= d::date and l.date_to >= d::date)
      order by 1`, [from, to]),
    sql.query(`
      select distinct on (applies_to) applies_to, break_minutes,
        (extract(epoch from (shift_end - shift_start)) / 60 - break_minutes)::int as net_minutes,
        (select (value #>> '{}')::int from transport.settings where key = 'prep_minutes') as prep_minutes
      from transport.working_hours where effective_from <= $1 order by applies_to, effective_from desc`, [to]),
    sql.query(`
      select run_date::text as date, vehicle, vehicle_type, in_kpi, runs::int, planned_drops::int, completed_drops::int,
             failed_drops::int, transport.target_on('van_drops_per_day', run_date)::float8 as target
      from transport.v_vehicle_day
      where run_date between $1 and $2 and operated
      order by run_date, vehicle`, [from, to]),
    // MaxOptra's run cost: its time and mileage rates applied to each planned run
    sql.query(`
      select coalesce(v.display_name, v.maxoptra_name) as vehicle, sum(r.run_cost)::float8 as est_cost,
             (count(*) filter (where r.run_cost is not null))::int as runs_costed
      from transport.runs r join transport.vehicles v on v.id = r.vehicle_id
      where r.run_date between $1 and $2 and r.removed_at is null
      group by 1`, [from, to]),
  ]);
  const costBy = Object.fromEntries(costs.map((c) => [c.vehicle, c]));
  const withPay = user.pay;                       // driver pay, and totals that include it, need pay access
  for (const v of vehicles) if (withPay) v.est_cost = costBy[v.vehicle] ? costBy[v.vehicle].est_cost : null;   // built from MaxOptra's per-driver hourly rates
  let external = null, salariesIdle = null;
  {
    const [byType, byReason] = await Promise.all([
      sql.query(`select coalesce(job_type, 'unclassified') as job_type, count(*)::int as jobs, sum(job_cost)::float8 as cost,
                        (count(*) filter (where job_cost is null))::int as no_cost
                 from transport.v_external_jobs where job_date between $1 and $2 group by 1 order by 1`, [from, to]),
      sql.query(`select coalesce(j.reason_code, 'none') as reason_code, coalesce(r.description, 'No reason given') as description,
                        count(*)::int as jobs, sum(j.job_cost)::float8 as cost
                 from transport.v_external_jobs j left join transport.reason_codes r on r.code = j.reason_code
                 where j.job_date between $1 and $2 group by 1, 2 order by 4 desc nulls last`, [from, to]),
    ]);
    external = { by_type: byType, by_reason: byReason };
  }
  {
    const [plus, lease, salaries] = await Promise.all([
      sql.query(`
        select coalesce(v.display_name, v.maxoptra_name) as vehicle,
          sum(c.driver_cost)::float8 as driver, sum(c.fuel_cost)::float8 as fuel, sum(c.fuel_miles)::float8 as fuel_miles,
          (count(*) filter (where c.fuel_on_actual))::int as runs_fuel_actual, count(*)::int as runs,
          (count(*) filter (where c.driver_rate_missing))::int as runs_no_driver_rate,
          bool_or(c.mpg_missing) as mpg_missing, bool_or(c.fuel_price_missing) as fuel_price_missing
        from transport.run_costs($1::date, $2::date) c join transport.vehicles v on v.id = c.vehicle_id
        group by 1`, [from, to]),
      sql.query(`select coalesce(v.display_name, v.maxoptra_name) as vehicle, p.lease_cost::float8 as lease, p.weekdays
                 from transport.period_lease($1::date, $2::date) p join transport.vehicles v on v.id = p.vehicle_id`, [from, to]),
      // salaried drivers are paid every weekday; what isn't already in a run's cost is non-driving days
      sql.query(`
        with paid as (select driver_id, salary_cost from transport.period_salaries($1::date, $2::date)),
             used as (select driver_id, sum(driver_cost) as allocated from transport.run_costs($1::date, $2::date)
                      where driver_basis = 'salary_monthly' group by 1)
        select coalesce(sum(greatest(p.salary_cost - coalesce(u.allocated, 0), 0)), 0)::float8 as idle_cost,
               count(*)::int as salaried_drivers
        from paid p left join used u using (driver_id)`, [from, to]).then((r) => (withPay ? r : [null])),
    ]);
    salariesIdle = withPay ? salaries[0] : null;
    const plusBy = Object.fromEntries(plus.map((c) => [c.vehicle, c]));
    const leaseBy = Object.fromEntries(lease.map((c) => [c.vehicle, c]));
    for (const v of vehicles) {
      const c = plusBy[v.vehicle];
      const l = leaseBy[v.vehicle];
      if (!c && !l) { v.cost = null; continue; }
      const missing = [];
      if (withPay && c && c.runs_no_driver_rate) missing.push(`driver pay on ${c.runs_no_driver_rate} run${c.runs_no_driver_rate === 1 ? '' : 's'}`);
      if (!l) missing.push('lease');
      if (c && c.mpg_missing) missing.push('MPG');
      if (c && c.fuel_price_missing) missing.push('fuel price');
      const parts = [withPay && c ? c.driver : null, l ? l.lease : null, c ? c.fuel : null];
      v.cost = { total: parts.some((x) => x !== null) ? parts.reduce((t, x) => t + (x || 0), 0) : null,
                 ...(withPay ? { driver: c ? c.driver : null } : {}), lease: l ? l.lease : null, lease_weekdays: l ? l.weekdays : 0,
                 fuel: c ? c.fuel : null, fuel_miles: c ? c.fuel_miles : null, includes_pay: Boolean(withPay),
                 runs_fuel_actual: c ? c.runs_fuel_actual : 0, runs: c ? c.runs : 0, missing };
    }
  }
  // Utilisation (brief s.24): estimated working time (loading allowance + first departure to return, less the
  // break) against the scheduled net day for vans or trucks.
  const hoursBy = Object.fromEntries(hours.map((h) => [h.applies_to, h]));
  for (const v of vehicles) {
    const h = hoursBy[v.hours_profile];
    v.scheduled_minutes = h ? h.net_minutes : null;
    v.utilisation = v.avg_day_minutes && h
      ? Math.round(((v.avg_day_minutes + (h.prep_minutes ?? 25) - h.break_minutes) / h.net_minutes) * 100) : null;
  }
  return json({ from, to, vehicles, drivers, failures, daily, vehicle_daily: vehicleDaily, missing_weekdays: missing.map((m) => m.date),
                external, ...(withPay ? { salaries_idle: salariesIdle } : {}) });
}

// ---------------------------------------------------------------------------
// Admin: cost rates, vehicles, drivers, users and jobs sent by courier. Every route here is Admins only.
// ---------------------------------------------------------------------------

const RATE_TYPES = {
  driver: ['day_rate', 'salary_monthly'], vehicle: ['lease_monthly', 'hire_daily', 'mpg'], fuel: ['price_per_litre'],
  external: ['same_day', 'overnight_parcel', 'overnight_pallet', 'other'],
};
const VEHICLE_TYPES = ['full_time_van', 'truck', 'support', 'temporary', 'excluded', 'unclassified'];
const DRIVER_TYPES = ['van', 'truck', 'manager', 'agency', 'excluded', 'unclassified'];
const JOB_TYPES = ['same_day', 'overnight_parcel', 'overnight_pallet', 'other'];

async function adminState(sql) {
  const [users, drivers, vehicles, rates, history, unplanned, fuel, reminderCfg, reminders] = await Promise.all([
    sql.query(`select email, role, display_name, active, courier_access from transport.app_users order by role, email`),
    sql.query(`
      select d.id, d.name, d.driver_type, d.kpi_included, d.active,
        coalesce((select string_agg(a.raw_name, ', ' order by a.raw_name) from transport.driver_aliases a where a.driver_id = d.id), '') as spellings,
        (select max(r.run_date)::text from transport.runs r where r.driver_id = d.id and r.removed_at is null) as last_run,
        (select count(*)::int from transport.runs r where r.driver_id = d.id and r.removed_at is null
           and r.run_date > (now() at time zone 'Europe/London')::date - 90) as runs_90
      from transport.drivers d order by d.name`),
    sql.query(`
      select v.id, v.maxoptra_name, coalesce(v.display_name, v.maxoptra_name) as vehicle, v.vehicle_type, v.kpi_included, v.active, v.notes,
        (select max(r.run_date)::text from transport.runs r where r.vehicle_id = v.id and r.removed_at is null) as last_run
      from transport.vehicles v order by case v.vehicle_type when 'full_time_van' then 1 when 'truck' then 2 when 'support' then 3 else 4 end, 3`),
    // the latest rate of each kind, with the date it applies from
    sql.query(`select distinct on (subject_type, coalesce(subject_id, 0), rate_type)
                 subject_type, subject_id, rate_type, value::float8, effective_from::text
               from transport.cost_rates order by subject_type, coalesce(subject_id, 0), rate_type, effective_from desc`),
    sql.query(`select c.subject_type, c.subject_id, c.rate_type, c.value::float8, c.effective_from::text, c.created_by, c.created_at,
                 coalesce(d.name, coalesce(v.display_name, v.maxoptra_name)) as subject
               from transport.cost_rates c
               left join transport.drivers d on c.subject_type = 'driver' and d.id = c.subject_id
               left join transport.vehicles v on c.subject_type = 'vehicle' and v.id = c.subject_id
               where c.subject_type in ('vehicle', 'fuel')
               order by c.created_at desc limit 40`),
    sql.query(`select count(*)::int as jobs, min(job_date)::text as first_date from transport.external_jobs where removed_at is null`),
    sql.query(`select effective_from::text as week_start, value::float8 as price, created_by, created_at
               from transport.cost_rates where subject_type = 'fuel' and rate_type = 'price_per_litre'
               order by effective_from desc limit 16`),
    sql.query(`select value from transport.settings where key = 'fuel_reminder'`),
    sql.query(`select sent_at, week_start::text, recipients, ok, message from transport.reminder_log
               where kind = 'fuel' order by sent_at desc limit 5`),
  ]);
  const rateOf = (type, id, rate) => rates.find((r) => r.subject_type === type && (r.subject_id ?? null) === (id ?? null) && r.rate_type === rate) || null;

  for (const v of vehicles) for (const k of RATE_TYPES.vehicle) v[k] = rateOf('vehicle', v.id, k);
  const settings = { fuel_price: rateOf('fuel', null, 'price_per_litre') };
  const today = londonNow().date;
  const d = new Date(`${today}T12:00:00Z`);
  const weekStart = new Date(d.getTime() - ((d.getUTCDay() + 6) % 7) * 86400000).toISOString().slice(0, 10);
  return json({ users, drivers, vehicles, settings, history, unplanned: unplanned[0],
                fuel: { prices: fuel, week_start: weekStart, this_week: fuel.find((f) => f.week_start >= weekStart) || null },
                reminder: { ...(reminderCfg[0] ? reminderCfg[0].value : {}), recent: reminders },
                history_start: '2026-06-01', today });
}

// Each section may only set its own kinds of rate: Admin vehicles and fuel, Pay drivers, Couriers job prices.
async function saveRates(request, sql, user, allowed) {
  const b = await request.json().catch(() => ({}));
  if (!isDate(b.effective_from)) return fail(400, 'Choose the date the rates apply from');
  const rows = Array.isArray(b.rates) ? b.rates : [];
  const clean = [];
  for (const r of rows) {
    if (!allowed.includes(r.subject_type)) return fail(403, `This section can't change ${r.subject_type} rates`);
    const types = RATE_TYPES[r.subject_type];
    const value = Number(r.value);
    if (!types || !types.includes(r.rate_type) || !Number.isFinite(value) || value < 0) return fail(400, `Not a valid rate: ${JSON.stringify(r)}`);
    if (r.rate_type === 'mpg' && value === 0) return fail(400, 'MPG cannot be 0');
    const needsId = r.subject_type === 'driver' || r.subject_type === 'vehicle';
    if (needsId && !Number.isInteger(r.subject_id)) return fail(400, 'Rate is missing its driver or vehicle');
    clean.push([r.subject_type, needsId ? r.subject_id : null, r.rate_type, value]);
  }
  for (const [type, id, rate, value] of clean) {
    await sql.query(
      `insert into transport.cost_rates (subject_type, subject_id, rate_type, value, effective_from, created_by)
       values ($1, $2, $3, $4, $5, $6)
       on conflict (subject_type, coalesce(subject_id, 0), rate_type, effective_from)
       do update set value = excluded.value, created_by = excluded.created_by, created_at = now()`,
      [type, id, rate, value, b.effective_from, user.email]);
  }
  return json({ saved: clean.length });
}

async function saveReminder(request, sql) {
  const b = await request.json().catch(() => ({}));
  const recipients = [...new Set((Array.isArray(b.recipients) ? b.recipients : []).map((e) => String(e).trim().toLowerCase()).filter(Boolean))];
  const bad = recipients.filter((e) => !/^[^@\s]+@pluspkg\.com$/.test(e));
  if (bad.length) return fail(400, `Use Plus Packaging email addresses: ${bad.join(', ')}`);
  const startDay = Number(b.start_day), hour = Number(b.hour);
  if (!Number.isInteger(startDay) || startDay < 1 || startDay > 5) return fail(400, 'Choose a weekday to start reminding');
  if (!Number.isInteger(hour) || hour < 6 || hour > 17) return fail(400, 'Choose a time between 06:00 and 17:00');
  const value = { enabled: Boolean(b.enabled) && recipients.length > 0, recipients, start_day: startDay, hour };
  await sql.query(`insert into transport.settings (key, value, description) values ('fuel_reminder', $1::jsonb, 'Weekly fuel price reminder')
                   on conflict (key) do update set value = excluded.value, updated_at = now()`, [JSON.stringify(value)]);
  return json({ saved: value });
}

async function fuelState(sql, user) {
  const [prices, cfg, recent] = await Promise.all([
    sql.query(`select effective_from::text as week_start, value::float8 as price, created_by, created_at
               from transport.cost_rates where subject_type = 'fuel' and rate_type = 'price_per_litre'
               order by effective_from desc limit 26`),
    sql.query(`select value from transport.settings where key = 'fuel_reminder'`),
    sql.query(`select sent_at, week_start::text, recipients, ok, message from transport.reminder_log
               where kind = 'fuel' order by sent_at desc limit 5`),
  ]);
  const today = londonNow().date;
  const d = new Date(`${today}T12:00:00Z`);
  const weekStart = new Date(d.getTime() - ((d.getUTCDay() + 6) % 7) * 86400000).toISOString().slice(0, 10);
  return json({ prices, week_start: weekStart, this_week: prices.find((f) => f.week_start >= weekStart) || null, today,
                can_edit: user.couriers,
                ...(user.couriers ? { reminder: { ...(cfg[0] ? cfg[0].value : {}), recent } } : {}) });
}

async function saveFuelPrice(request, sql, user) {
  const b = await request.json().catch(() => ({}));
  const price = Number(b.price);
  if (!isDate(b.week_start)) return fail(400, 'Choose the week the price is for');
  if (!(price > 0) || price > 10) return fail(400, 'Enter the price per litre in pounds, for example 1.429');
  await sql.query(
    `insert into transport.cost_rates (subject_type, subject_id, rate_type, value, effective_from, created_by)
     values ('fuel', null, 'price_per_litre', $1, $2, $3)
     on conflict (subject_type, coalesce(subject_id, 0), rate_type, effective_from)
     do update set value = excluded.value, created_by = excluded.created_by, created_at = now()`,
    [price, b.week_start, user.email]);
  return json({ saved: price, week_start: b.week_start });
}

async function saveUser(request, sql) {
  const b = await request.json().catch(() => ({}));
  const email = String(b.email || '').trim().toLowerCase();
  if (!/^[^@\s]+@pluspkg\.com$/.test(email)) return fail(400, 'Use a Plus Packaging email address');
  const role = b.role === 'admin' ? 'admin' : 'standard';
  const active = b.active !== false;
  const couriers = Boolean(b.courier_access);
  if (role !== 'admin' || !active) {
    const others = await sql.query(`select count(*)::int as n from transport.app_users where role = 'admin' and active and email <> $1`, [email]);
    if (others[0].n === 0) return fail(400, 'There must always be at least one Admin');
  }
  await sql.query(
    `insert into transport.app_users (email, role, display_name, active, courier_access) values ($1, $2, $3, $4, $5)
     on conflict (email) do update set role = excluded.role, active = excluded.active, courier_access = excluded.courier_access,
       display_name = coalesce(excluded.display_name, transport.app_users.display_name)`,
    [email, role, b.display_name ? String(b.display_name).slice(0, 80) : null, active, couriers]);
  return json({ saved: email });
}

async function saveVehicle(request, sql) {
  const b = await request.json().catch(() => ({}));
  if (!Number.isInteger(b.id) || !VEHICLE_TYPES.includes(b.vehicle_type)) return fail(400, 'Not a valid vehicle change');
  await sql.query(
    `update transport.vehicles set vehicle_type = $2, kpi_included = $3, hours_profile = case when $2 = 'truck' then 'truck' else hours_profile end,
       notes = $4, updated_at = now() where id = $1`,
    [b.id, b.vehicle_type, Boolean(b.kpi_included), b.notes ? String(b.notes).slice(0, 500) : null]);
  return json({ saved: b.id });
}

async function saveDriver(request, sql) {
  const b = await request.json().catch(() => ({}));
  if (!Number.isInteger(b.id) || !DRIVER_TYPES.includes(b.driver_type)) return fail(400, 'Not a valid driver change');
  await sql.query(`update transport.drivers set driver_type = $2, kpi_included = $3, updated_at = now() where id = $1`,
    [b.id, b.driver_type, Boolean(b.kpi_included)]);
  return json({ saved: b.id });
}

async function mergeDrivers(request, sql) {
  const b = await request.json().catch(() => ({}));
  if (!Number.isInteger(b.from_id) || !Number.isInteger(b.into_id) || b.from_id === b.into_id) return fail(400, 'Choose two different drivers');
  await sql.query('select transport.merge_drivers($1, $2)', [b.from_id, b.into_id]);
  return json({ merged: b.from_id, into: b.into_id });
}

// ---------------------------------------------------------------------------
// Pay: driver day rates and monthly salaries. Only people with pay access can open it or give it to anyone, and
// every view and change is logged.
// ---------------------------------------------------------------------------
async function audit(sql, user, action, detail) {
  await sql.query('insert into transport.audit_log (email, action, detail) values ($1, $2, $3)', [user.email, action, detail ? JSON.stringify(detail) : null]);
}

async function payState(sql, user) {
  await audit(sql, user, 'pay.view');
  const [drivers, pay, history, people, log] = await Promise.all([
    sql.query(`
      select d.id, d.name, d.driver_type, d.kpi_included,
        (select max(r.run_date)::text from transport.runs r where r.driver_id = d.id and r.removed_at is null) as last_run,
        (select count(*)::int from transport.runs r where r.driver_id = d.id and r.removed_at is null
           and r.run_date > (now() at time zone 'Europe/London')::date - 90) as runs_90
      from transport.drivers d order by d.name`),
    sql.query(`select distinct on (subject_id) subject_id, rate_type as basis, value::float8, effective_from::text
               from transport.cost_rates where subject_type = 'driver' and rate_type in ('day_rate', 'salary_monthly')
               order by subject_id, effective_from desc, created_at desc`),
    sql.query(`select c.subject_id, d.name, c.rate_type as basis, c.value::float8, c.effective_from::text, c.created_by, c.created_at
               from transport.cost_rates c left join transport.drivers d on d.id = c.subject_id
               where c.subject_type = 'driver' order by c.created_at desc limit 60`),
    sql.query(`select email, role, active from transport.app_users where pay_access order by email`),
    sql.query(`select at, email, action, detail from transport.audit_log where action like 'pay.%' order by at desc limit 40`),
  ]);
  const payBy = Object.fromEntries(pay.map((p) => [p.subject_id, p]));
  for (const d of drivers) d.pay = payBy[d.id] || null;
  return json({ drivers, history, people, log, today: londonNow().date, history_start: '2026-06-01' });
}

async function savePay(request, sql, user) {
  const b = await request.json().catch(() => ({}));
  if (!isDate(b.effective_from)) return fail(400, 'Choose the date the pay applies from');
  const rows = Array.isArray(b.pay) ? b.pay : [];
  for (const r of rows) {
    if (!Number.isInteger(r.driver_id) || !['day_rate', 'salary_monthly'].includes(r.basis) || !(Number(r.value) >= 0)) return fail(400, 'Not a valid pay entry');
  }
  for (const r of rows) {
    await sql.query(
      `insert into transport.cost_rates (subject_type, subject_id, rate_type, value, effective_from, created_by)
       values ('driver', $1, $2, $3, $4, $5)
       on conflict (subject_type, coalesce(subject_id, 0), rate_type, effective_from)
       do update set value = excluded.value, created_by = excluded.created_by, created_at = now()`,
      [r.driver_id, r.basis, Number(r.value), b.effective_from, user.email]);
  }
  await audit(sql, user, 'pay.change', { effective_from: b.effective_from, drivers: rows.map((r) => r.driver_id) });
  return json({ saved: rows.length });
}

async function savePayAccess(request, sql, user) {
  const b = await request.json().catch(() => ({}));
  const email = String(b.email || '').trim().toLowerCase();
  if (!/^[^@\s]+@pluspkg\.com$/.test(email)) return fail(400, 'Use a Plus Packaging email address');
  const give = Boolean(b.pay_access);
  if (!give) {
    const others = await sql.query(`select count(*)::int as n from transport.app_users where pay_access and active and email <> $1`, [email]);
    if (others[0].n === 0) return fail(400, 'At least one person must keep pay access');
  }
  await sql.query(
    `insert into transport.app_users (email, role, active, pay_access) values ($1, 'standard', true, $2)
     on conflict (email) do update set pay_access = excluded.pay_access`, [email, give]);
  await audit(sql, user, give ? 'pay.access_given' : 'pay.access_removed', { email });
  return json({ saved: email, pay_access: give });
}

// ---------------------------------------------------------------------------
// Couriers and pallets: jobs that didn't go on a Plus vehicle, their reason codes and costs.
// ---------------------------------------------------------------------------
async function courierState(sql, user) {
  const [codes, rates, counts] = await Promise.all([
    sql.query(`select code, description, active, sort_order from transport.reason_codes order by sort_order, code`),
    sql.query(`select distinct on (rate_type) rate_type, value::float8, effective_from::text from transport.cost_rates
               where subject_type = 'external' order by rate_type, effective_from desc`),
    sql.query(`select count(*)::int as jobs, (count(*) filter (where source = 'manual'))::int as manual
               from transport.external_jobs where removed_at is null`),
  ]);
  const defaults = Object.fromEntries(rates.map((r) => [r.rate_type, r]));
  return json({ codes, defaults, counts: counts[0], can_edit: user.couriers, today: londonNow().date, history_start: '2026-06-01' });
}

async function saveReason(request, sql) {
  const b = await request.json().catch(() => ({}));
  const code = String(b.code || '').trim().toUpperCase();
  const description = String(b.description || '').trim();
  if (!/^[A-Z0-9][A-Z0-9 _-]{0,19}$/.test(code)) return fail(400, 'Use a short code: letters, numbers, spaces, - or _ (up to 20)');
  if (!description) return fail(400, 'Give the reason a description');
  const was = b.was ? String(b.was).trim().toUpperCase() : null;
  if (was && was !== code) {
    await sql.query(`update transport.reason_codes set code = $2, description = $3, active = $4, sort_order = $5 where code = $1`,
      [was, code, description.slice(0, 200), b.active !== false, Number.isInteger(b.sort_order) ? b.sort_order : 100]);
  } else {
    await sql.query(
      `insert into transport.reason_codes (code, description, active, sort_order) values ($1, $2, $3, $4)
       on conflict (code) do update set description = excluded.description, active = excluded.active, sort_order = excluded.sort_order`,
      [code, description.slice(0, 200), b.active !== false, Number.isInteger(b.sort_order) ? b.sort_order : 100]);
  }
  return json({ saved: code });
}

async function courierJobs(url, sql) {
  const from = url.searchParams.get('from'), to = url.searchParams.get('to');
  if (!isDate(from) || !isDate(to)) return fail(400, 'Give from and to as YYYY-MM-DD');
  const jobs = await sql.query(`
    select order_ref, job_date::text, client_name, location_name, location_postcode, vehicle_requirements,
           size_1::float8, size_2::float8, order_status, job_type, reason_code, cost::float8, job_cost::float8,
           cost_is_default, notes, source, created_by, updated_by
    from transport.v_external_jobs where job_date between $1 and $2 order by job_date desc, client_name limit 1000`, [from, to]);
  return json({ from, to, jobs });
}

async function saveCourierJob(request, sql, user) {
  const b = await request.json().catch(() => ({}));
  const ref = String(b.order_ref || '').trim();
  if (!ref || !isDate(b.job_date)) return fail(400, 'Give the order reference and date');
  if (b.job_type && !JOB_TYPES.includes(b.job_type)) return fail(400, 'Not a valid job type');
  const cost = b.cost === null || b.cost === '' || b.cost === undefined ? null : Number(b.cost);
  if (cost !== null && (!Number.isFinite(cost) || cost < 0)) return fail(400, 'Cost must be a positive amount');
  const reason = b.reason_code ? String(b.reason_code).toUpperCase() : null;
  if (reason) {
    const ok = await sql.query('select 1 from transport.reason_codes where code = $1', [reason]);
    if (!ok.length) return fail(400, `No reason code ${reason}`);
  }
  if (b.new) {
    const rows = await sql.query(
      `insert into transport.external_jobs (order_ref, job_date, client_name, location_postcode, job_type, reason_code, cost, notes, source, created_by, updated_by)
       values ($1, $2, $3, $4, $5, $6, $7, $8, 'manual', $9, $9)
       on conflict (order_ref, job_date) do nothing returning order_ref`,
      [ref, b.job_date, b.client_name ? String(b.client_name).slice(0, 200) : null, b.location_postcode ? String(b.location_postcode).toUpperCase().slice(0, 12) : null,
       b.job_type || null, reason, cost, b.notes ? String(b.notes).slice(0, 500) : null, user.email]);
    return rows.length ? json({ saved: ref }) : fail(409, `${ref} is already listed for that date`);
  }
  const rows = await sql.query(
    `update transport.external_jobs set job_type = $3, reason_code = $4, cost = $5, notes = $6, updated_at = now(), updated_by = $7,
       removed_at = null where order_ref = $1 and job_date = $2 returning order_ref`,
    [ref, b.job_date, b.job_type || null, reason, cost, b.notes ? String(b.notes).slice(0, 500) : null, user.email]);
  return rows.length ? json({ saved: ref }) : fail(404, 'Job not found');
}

async function removeCourierJob(request, sql, user) {
  const b = await request.json().catch(() => ({}));
  const rows = await sql.query(
    `update transport.external_jobs set removed_at = now(), updated_by = $3 where order_ref = $1 and job_date = $2 and source = 'manual' returning order_ref`,
    [String(b.order_ref || ''), b.job_date, user.email]);
  return rows.length ? json({ removed: b.order_ref }) : fail(404, 'Only jobs added by hand can be removed');
}

async function importBatch(request, sql) {
  const text = await request.text();
  if (text.length > MAX_IMPORT_BYTES) return fail(413, 'Import batch too large; the page sends it in smaller parts');
  let body;
  try { body = JSON.parse(text); } catch { return fail(400, 'Import batch is not valid JSON'); }
  const runs = Array.isArray(body.runs) ? body.runs : [];
  const orders = Array.isArray(body.orders) ? body.orders : [];
  const rows = await sql.query('select transport.import_batch($1::jsonb, $2::jsonb, $3) as result',
    [JSON.stringify(runs), JSON.stringify(orders), 'report_xlsx']);
  return json(rows[0].result);
}

async function importLog(request, sql, user) {
  const b = await request.json().catch(() => ({}));
  const statusValue = b.status === 'ok' ? 'ok' : 'error';
  await sql.query(
    `insert into transport.sync_log (source, status, finished_at, date_from, date_to, runs_upserted, orders_upserted, message, triggered_by)
     values ('report_xlsx', $1, now(), $2, $3, $4, $5, $6, $7)`,
    [statusValue, isDate(b.from) ? b.from : null, isDate(b.to) ? b.to : null,
     Number.isFinite(b.runs) ? b.runs : null, Number.isFinite(b.orders) ? b.orders : null,
     String(b.message || '').slice(0, 2000), user.email]);
  return json({ logged: true });
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export async function onRequest(context) {
  const { request, env, params } = context;
  const route = [].concat(params.path || []).join('/');
  const method = request.method.toUpperCase();
  const url = new URL(request.url);

  const missing = missingSettings(env);
  if (missing.length) return fail(500, 'The transport API is missing settings', `Add ${missing.join(', ')} in Pages > Settings > Variables and Secrets, then redeploy`);

  try {
    const sql = neon(env.TRANSPORT_DATABASE_URL);
    const { user, error } = await identify(request, env, sql);
    if (error) return error;
    const admin = user.role === 'admin';

    if (method === 'GET' && route === 'me') return json(user);
    if (method === 'GET' && route === 'status') return status(sql);
    if (method === 'GET' && route === 'validation') return validation(url, sql);
    if (method === 'GET' && route === 'live') return live(sql, user);
    if (method === 'GET' && route === 'day') return day(url, sql, user);
    if (method === 'GET' && route === 'customer') return customer(url, sql);
    if (method === 'GET' && route === 'report') return report(url, sql, user);
    if (route.startsWith('pay')) {
      if (!user.pay) return fail(403, 'Pay is restricted');
      if (method === 'GET' && route === 'pay/state') return payState(sql, user);
      if (method === 'POST' && route === 'pay/rates') return savePay(request, sql, user);
      if (method === 'POST' && route === 'pay/access') return savePayAccess(request, sql, user);
      return fail(404, `No pay route for ${method} /api/transport/${route}`);
    }
    if (route.startsWith('fuel')) {
      if (method === 'GET' && route === 'fuel/state') return fuelState(sql, user);
      if (!user.couriers) return fail(403, 'Fuel prices are entered by Admins and people with courier access');
      if (method === 'POST' && route === 'fuel/price') return saveFuelPrice(request, sql, user);
      if (method === 'POST' && route === 'fuel/reminder') return saveReminder(request, sql);
      return fail(404, `No fuel route for ${method} /api/transport/${route}`);
    }
    if (route.startsWith('couriers')) {
      // everyone can see courier jobs and their costs; changes need courier access or Admin
      if (method === 'GET' && route === 'couriers/state') return courierState(sql, user);
      if (method === 'GET' && route === 'couriers/jobs') return courierJobs(url, sql);
      if (!user.couriers) return fail(403, 'Changes here need courier access');
      if (method === 'POST' && route === 'couriers/reason') return saveReason(request, sql);
      if (method === 'POST' && route === 'couriers/defaults') return saveRates(request, sql, user, ['external']);
      if (method === 'POST' && route === 'couriers/job') return saveCourierJob(request, sql, user);
      if (method === 'POST' && route === 'couriers/job/remove') return removeCourierJob(request, sql, user);
      return fail(404, `No couriers route for ${method} /api/transport/${route}`);
    }
    if (route.startsWith('admin')) {
      if (!admin) return fail(403, 'Admins only');
      if (method === 'GET' && route === 'admin/state') return adminState(sql);
      if (method === 'POST' && route === 'admin/rates') return saveRates(request, sql, user, ['vehicle', 'fuel']);
      if (method === 'POST' && route === 'admin/user') return saveUser(request, sql);
      if (method === 'POST' && route === 'admin/vehicle') return saveVehicle(request, sql);
      if (method === 'POST' && route === 'admin/driver') return saveDriver(request, sql);
      if (method === 'POST' && route === 'admin/merge-drivers') return mergeDrivers(request, sql);
      return fail(404, `No admin route for ${method} /api/transport/${route}`);
    }
    if (method === 'POST' && route === 'import') return admin ? importBatch(request, sql) : fail(403, 'Admins only');
    if (method === 'POST' && route === 'import/log') return admin ? importLog(request, sql, user) : fail(403, 'Admins only');

    return fail(404, `No transport API route for ${method} /api/transport/${route}`);
  } catch (e) {
    return fail(500, 'The transport API hit an error', e && e.message ? e.message : String(e));
  }
}
