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
  const rows = await sql.query('select role, active, display_name from transport.app_users where email = $1', [email]);
  const user = rows[0];
  const role = user && user.active && user.role === 'admin' ? 'admin' : 'standard';
  return { user: { email, role, name: (user && user.display_name) || null } };
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
           o.planned_arrival, o.planned_departure, o.eta,
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
      min(act_arr) as act_arr, max(act_dep) as act_dep, min(eta) as eta, max(client_name) as client
    from o group by run_key, stop_key
  )
  select r.run_key, r.run_number, r.vehicle_id, coalesce(v.display_name, v.maxoptra_name) as vehicle, v.vehicle_type,
    (v.kpi_included and (v.kpi_from is null or r.run_date >= v.kpi_from) and (v.kpi_to is null or r.run_date <= v.kpi_to)) as in_kpi,
    d.name as driver,
    r.planned_departure::text, r.actual_departure::text, r.planned_end::text, r.actual_end::text,
    count(s.stop_key)::int as stops,
    (count(s.stop_key) filter (where not s.done))::int as stops_open,
    (count(s.stop_key) filter (where s.is_drop))::int as planned_drops,
    (count(s.stop_key) filter (where s.is_drop and s.completed))::int as completed_drops,
    (count(s.stop_key) filter (where s.is_drop and s.failed))::int as failed_drops,
    (count(s.stop_key) filter (where s.is_drop and not s.done))::int as open_drops,
    min(s.act_arr)::text as first_arrival,
    (max(s.act_dep) filter (where s.done))::text as last_departure,
    ((array_agg(s.planned_arrival order by s.seq desc nulls last) filter (where s.done and s.act_arr is not null))[1])::text as last_done_planned,
    ((array_agg(s.act_arr order by s.seq desc nulls last) filter (where s.done and s.act_arr is not null))[1])::text as last_done_actual,
    ((array_agg(s.planned_arrival order by s.seq nulls last) filter (where not s.done))[1])::text as next_planned,
    ((array_agg(s.eta order by s.seq nulls last) filter (where not s.done))[1])::text as next_eta,
    (array_agg(s.client order by s.seq nulls last) filter (where not s.done))[1] as next_client,
    ((array_agg(s.planned_departure order by s.seq desc nulls last))[1])::text as last_stop_planned_departure
  from transport.runs r
  join transport.vehicles v on v.id = r.vehicle_id
  left join transport.drivers d on d.id = r.driver_id
  left join s on s.run_key = r.run_key
  where r.run_date = $1 and r.removed_at is null
  group by r.run_key, r.run_number, r.vehicle_id, v.display_name, v.maxoptra_name, v.vehicle_type, v.kpi_included,
           v.kpi_from, v.kpi_to, r.run_date, d.name, r.planned_departure, r.actual_departure, r.planned_end, r.actual_end
  order by 4, r.run_number`;

// Thresholds for live status, in minutes.
const LATE_AFTER = 10;          // nothing reported this long after the planned departure: Late
const NO_DATA_AFTER = 60;       // ...and after this long: No data (the driver app probably isn't in use)
const BACK_AFTER_ESTIMATE = 30; // returning, and this long past the estimated return: treated as back

export function runState(run, now) {
  const leg = minutesBetween(run.last_stop_planned_departure, run.planned_end);
  const estimatedReturn = run.stops > 0 && run.stops_open === 0 && run.last_departure && leg !== null && leg >= 0 && leg <= 300
    ? addMinutes(run.last_departure, leg) : null;
  const started = Boolean(run.actual_departure || run.first_arrival || run.stops_open < run.stops);
  let status;
  let variance = null;                           // minutes: positive = ahead of plan
  if (run.actual_end) status = 'back';
  else if (run.stops > 0 && run.stops_open === 0) {
    status = estimatedReturn && minutesBetween(estimatedReturn, now) > BACK_AFTER_ESTIMATE ? 'back_estimated' : 'returning';
  } else if (!started) {
    const late = run.planned_departure ? minutesBetween(run.planned_departure, now) : null;
    if (late === null || late < LATE_AFTER) status = 'not_departed';
    else if (late < NO_DATA_AFTER) { status = 'late'; variance = -late; }
    else status = 'no_data';
  } else status = 'out';
  if (status === 'out') {
    if (run.next_eta && run.next_planned) variance = minutesBetween(run.next_eta, run.next_planned);
    else if (run.last_done_actual && run.last_done_planned) variance = minutesBetween(run.last_done_actual, run.last_done_planned);
  } else if (['returning', 'back', 'back_estimated'].includes(status) && run.last_done_actual && run.last_done_planned) {
    variance = minutesBetween(run.last_done_actual, run.last_done_planned);
  }
  return { status, variance, estimated_return: estimatedReturn };
}

const STATUS_ORDER = ['out', 'returning', 'late', 'no_data', 'not_departed', 'back_estimated', 'back'];

export function buildLive(runs, now) {
  const vehicles = new Map();
  for (const r of runs) {
    const state = runState(r, now);
    const run = { run_number: r.run_number, driver: r.driver, ...state,
      planned_drops: r.planned_drops, completed_drops: r.completed_drops, failed_drops: r.failed_drops, open_drops: r.open_drops,
      planned_departure: clock(r.planned_departure), actual_departure: clock(r.actual_departure),
      planned_return: clock(r.planned_end), actual_return: clock(r.actual_end),
      estimated_return: clock(state.estimated_return), last_job: clock(r.last_departure),
      next_client: r.next_client, next_due: clock(r.next_eta || r.next_planned) };
    if (!vehicles.has(r.vehicle_id)) vehicles.set(r.vehicle_id, { vehicle: r.vehicle, vehicle_type: r.vehicle_type, in_kpi: r.in_kpi, runs: [] });
    vehicles.get(r.vehicle_id).runs.push(run);
  }
  const list = [...vehicles.values()].map((v) => {
    const current = [...v.runs].sort((a, b) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) || a.run_number - b.run_number)[0];
    const sum = (k) => v.runs.reduce((t, r) => t + (r[k] || 0), 0);
    const first = v.runs[0];
    return { ...v, current, driver: current.driver,
      planned_drops: sum('planned_drops'), completed_drops: sum('completed_drops'), failed_drops: sum('failed_drops'), open_drops: sum('open_drops'),
      first_departure: first.actual_departure, first_departure_planned: first.planned_departure,
      last_job: v.runs.map((r) => r.last_job).filter(Boolean).sort().pop() || null,
      second_runs: v.runs.filter((r) => r.run_number >= 2).length };
  });
  const vans = list.filter((v) => v.vehicle_type === 'full_time_van' && v.in_kpi && v.planned_drops > 0);
  const out = list.filter((v) => ['out', 'returning', 'late', 'no_data'].includes(v.current.status));
  const sum = (arr, k) => arr.reduce((t, x) => t + (x[k] || 0), 0);
  return {
    vehicles: list,
    headline: {
      planned_drops: sum(list, 'planned_drops'), completed_drops: sum(list, 'completed_drops'),
      failed_drops: sum(list, 'failed_drops'), open_drops: sum(list, 'open_drops'),
      van_count: vans.length, van_completed: sum(vans, 'completed_drops'),
      vans_active: list.filter((v) => ['full_time_van', 'support'].includes(v.vehicle_type)).length,
      trucks_active: list.filter((v) => v.vehicle_type === 'truck').length,
      vehicles_out: out.length, vehicles_returning: list.filter((v) => v.current.status === 'returning').length,
      second_runs: sum(list, 'second_runs'),
    },
  };
}

async function live(sql) {
  const now = londonNow();
  const [runs, sync, events, target] = await Promise.all([
    sql.query(LIVE_RUNS, [now.date]),
    sql.query(`select
        (select started_at from transport.sync_log where source = 'report_api' and status = 'ok' order by id desc limit 1) as last_ok,
        (select started_at from transport.sync_log where source = 'report_api' and status = 'error' order by id desc limit 1) as last_error_at,
        (select message from transport.sync_log where source = 'report_api' and status = 'error' order by id desc limit 1) as last_error`),
    sql.query(`select id, detail from transport.events where event_date = $1 and event_type = 'last_job_done'
               order by created_at desc, id desc limit 30`, [now.date]),
    sql.query(`select transport.target_on('van_drops_per_day', $1::date) as target`, [now.date]),
  ]);
  const s = sync[0] || {};
  const lastOk = s.last_ok ? londonNow(new Date(s.last_ok)) : null;
  const lastErr = s.last_error_at ? londonNow(new Date(s.last_error_at)) : null;
  const inHours = !['Sat', 'Sun'].includes(now.weekday) && now.minutes >= 6 * 60 && now.minutes < 19 * 60 + 30;
  const ageMin = s.last_ok ? Math.round((Date.now() - new Date(s.last_ok).getTime()) / 60000) : null;
  return json({
    date: now.date, now: now.stamp.slice(11, 16),
    sync: {
      last_ok: lastOk ? (lastOk.date === now.date ? lastOk.stamp.slice(11, 16) : lastOk.stamp.slice(0, 16)) : null,
      age_minutes: ageMin,
      stale: inHours && (ageMin === null || ageMin > 15),
      failing: Boolean(s.last_error_at && (!s.last_ok || new Date(s.last_error_at) > new Date(s.last_ok))),
      last_error: s.last_error || null, last_error_at: lastErr ? lastErr.stamp.slice(11, 16) : null,
    },
    target: target[0] && target[0].target !== null ? Number(target[0].target) : null,
    ...buildLive(runs, now.stamp),
    events: events.map((e) => ({ id: Number(e.id), ...e.detail,
      last_job_at: clock(e.detail.last_job_at && e.detail.last_job_at.replace('T', ' ')),
      estimated_return: clock(e.detail.estimated_return && e.detail.estimated_return.replace('T', ' ')),
      actual_return: clock(e.detail.actual_return && e.detail.actual_return.replace('T', ' ')) })),
  });
}

// ---------------------------------------------------------------------------
// Period report: any date range (the page asks for rolling month, rolling quarter or custom dates)
// ---------------------------------------------------------------------------

async function report(url, sql) {
  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');
  if (!isDate(from) || !isDate(to) || from > to) return fail(400, 'Give from and to as YYYY-MM-DD, from before to');
  if ((Date.parse(to) - Date.parse(from)) / 86400000 > 400) return fail(400, 'Choose a range of 400 days or less');

  const [vehicles, drivers, failures, daily, missing, hours] = await Promise.all([
    sql.query(`
      select vehicle, maxoptra_name, vehicle_type, hours_profile, bool_or(in_kpi) as in_kpi,
        (count(*) filter (where operated))::int as days,
        sum(planned_drops)::int as planned_drops, sum(completed_drops)::int as completed_drops,
        sum(failed_drops)::int as failed_drops, sum(second_runs)::int as second_runs,
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
      select driver_id, driver, (count(distinct run_date))::int as days, sum(completed_drops)::int as completed_drops,
        sum(failed_drops)::int as failed_drops, sum(second_runs)::int as second_runs,
        string_agg(distinct vehicle, ', ') as vehicles
      from transport.v_driver_day
      where run_date between $1 and $2 and vehicle_type = 'full_time_van' and driver_in_kpi
      group by driver_id, driver`, [from, to]),
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
        and not exists (select 1 from transport.runs r where r.run_date = d::date and r.removed_at is null)
      order by 1`, [from, to]),
    sql.query(`
      select distinct on (applies_to) applies_to, break_minutes,
        (extract(epoch from (shift_end - shift_start)) / 60 - break_minutes)::int as net_minutes,
        (select (value #>> '{}')::int from transport.settings where key = 'prep_minutes') as prep_minutes
      from transport.working_hours where effective_from <= $1 order by applies_to, effective_from desc`, [to]),
  ]);
  // Utilisation (brief s.24): estimated working time (loading allowance + first departure to return, less the
  // break) against the scheduled net day for vans or trucks.
  const hoursBy = Object.fromEntries(hours.map((h) => [h.applies_to, h]));
  for (const v of vehicles) {
    const h = hoursBy[v.hours_profile];
    v.scheduled_minutes = h ? h.net_minutes : null;
    v.utilisation = v.avg_day_minutes && h
      ? Math.round(((v.avg_day_minutes + (h.prep_minutes ?? 25) - h.break_minutes) / h.net_minutes) * 100) : null;
  }
  return json({ from, to, vehicles, drivers, failures, daily, missing_weekdays: missing.map((m) => m.date) });
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
    if (method === 'GET' && route === 'live') return live(sql);
    if (method === 'GET' && route === 'report') return report(url, sql);
    if (method === 'POST' && route === 'import') return admin ? importBatch(request, sql) : fail(403, 'Admins only');
    if (method === 'POST' && route === 'import/log') return admin ? importLog(request, sql, user) : fail(403, 'Admins only');

    return fail(404, `No transport API route for ${method} /api/transport/${route}`);
  } catch (e) {
    return fail(500, 'The transport API hit an error', e && e.message ? e.message : String(e));
  }
}
