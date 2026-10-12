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
                and not exists (select 1 from transport.runs r where r.run_date = d::date)) as weekdays_without_data
      from transport.runs where run_date between $1 and $2`,
      [from, to]),
  ]);
  return json({ from, to, vehicles, full_time_vans: totals[0], flags, coverage: coverage[0] });
}

async function status(sql) {
  const [range, recent] = await Promise.all([
    sql.query(`select min(run_date)::text as first_date, max(run_date)::text as last_date, count(*)::int as runs,
                      (select count(*)::int from transport.orders) as orders from transport.runs`),
    sql.query(`select source, status, started_at, finished_at, date_from::text, date_to::text, runs_upserted, orders_upserted,
                      message, triggered_by
               from transport.sync_log order by started_at desc limit 10`),
  ]);
  return json({ data: range[0], recent });
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
    if (method === 'POST' && route === 'import') return admin ? importBatch(request, sql) : fail(403, 'Admins only');
    if (method === 'POST' && route === 'import/log') return admin ? importLog(request, sql, user) : fail(403, 'Admins only');

    return fail(404, `No transport API route for ${method} /api/transport/${route}`);
  } catch (e) {
    return fail(500, 'The transport API hit an error', e && e.message ? e.message : String(e));
  }
}
