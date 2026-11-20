'use strict';
// ---------------------------------------------------------------------------
//  admin.js — command-line manager for the auth server.
//
//  Reads BASE_URL and ADMIN_TOKEN from .env (or env vars), then calls the
//  admin API. Run from the server/ folder.
//
//  Usage:
//    node admin.js create <login> <password> <days>
//    node admin.js extend <login> <days>
//    node admin.js ban    <login> [on|off]
//    node admin.js reset-hwid <login>
//    node admin.js delete <login>
//    node admin.js list
// ---------------------------------------------------------------------------
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');

const envPath = path.join(__dirname, '.env');
try { for (const l of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
  const m = l.match(/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)\s*$/);
  if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
} } catch (_) {}

const BASE = process.env.BASE_URL || ('http://127.0.0.1:' + (process.env.PORT || 3000));
const TOKEN = process.env.ADMIN_TOKEN || 'change-this-admin-token';

async function post(route, body) {
  const res = await fetch(new URL(route, BASE), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Admin-Token': TOKEN },
    body: JSON.stringify(body || {})
  });
  const text = await res.text();
  try { return { status: res.status, json: JSON.parse(text) }; }
  catch { return { status: res.status, json: { raw: text } }; }
}
async function get(route) {
  const res = await fetch(new URL(route, BASE), { headers: { 'X-Admin-Token': TOKEN } });
  const text = await res.text();
  try { return { status: res.status, json: JSON.parse(text) }; }
  catch { return { status: res.status, json: { raw: text } }; }
}
const fmtUntil = (u) => u ? new Date(u * 1000).toISOString().replace('T', ' ').slice(0, 19) : 'none';

async function main() {
  const [, , cmd, ...args] = process.argv;
  if (!cmd) return help();
  switch (cmd) {
    case 'create': {
      if (args.length < 3) return help();
      const r = await post('/api/admin/user', { login: args[0], password: args[1], days: Number(args[2]) });
      console.log(r.status === 200 ? `Created ${args[0]} until ${fmtUntil(r.json.until)}` : `ERROR ${r.status} ${JSON.stringify(r.json)}`);
      break;
    }
    case 'extend': {
      if (args.length < 2) return help();
      const r = await post('/api/admin/extend', { login: args[0], days: Number(args[1]) });
      console.log(r.status === 200 ? `Extended ${args[0]} until ${fmtUntil(r.json.until)}` : `ERROR ${r.status} ${JSON.stringify(r.json)}`);
      break;
    }
    case 'ban': {
      if (args.length < 1) return help();
      const banned = args[1] ? (args[1] !== 'off') : true;
      const r = await post('/api/admin/ban', { login: args[0], banned });
      console.log(r.status === 200 ? `${banned ? 'Banned' : 'Unbanned'} ${args[0]}` : `ERROR ${r.status} ${JSON.stringify(r.json)}`);
      break;
    }
    case 'reset-hwid': {
      if (args.length < 1) return help();
      const r = await post('/api/admin/reset-hwid', { login: args[0] });
      console.log(r.status === 200 ? `HWID reset for ${args[0]} (can bind a new device)` : `ERROR ${r.status} ${JSON.stringify(r.json)}`);
      break;
    }
    case 'delete': {
      if (args.length < 1) return help();
      const r = await post('/api/admin/delete', { login: args[0] });
      console.log(r.status === 200 ? `Deleted ${args[0]}` : `ERROR ${r.status} ${JSON.stringify(r.json)}`);
      break;
    }
    case 'list': {
      const r = await get('/api/admin/list');
      if (r.status !== 200) return console.log(`ERROR ${r.status} ${JSON.stringify(r.json)}`);
      const rows = r.json;
      if (!rows.length) return console.log('No users.');
      for (const u of rows) {
        console.log(`${u.login.padEnd(16)} hwid=${u.hwid || '-'.padEnd(19)}  sub=${fmtUntil(u.sub_until)}  banned=${u.banned}`);
      }
      break;
    }
    default: help();
  }
}
function help() {
  console.log(
    'Usage:\n' +
    '  node admin.js create <login> <password> <days>\n' +
    '  node admin.js extend <login> <days>\n' +
    '  node admin.js ban <login> [on|off]\n' +
    '  node admin.js reset-hwid <login>\n' +
    '  node admin.js delete <login>\n' +
    '  node admin.js list'
  );
}
main().catch(e => { console.error(e); process.exit(1); });
