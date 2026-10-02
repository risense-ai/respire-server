import assert from 'node:assert/strict';
import { parseRoute, pathRestToHash, routeHash } from '../src/hashRoute.js';

const userPages = ['memories', 'diary', 'sessions', 'keys', 'security'];
const adminPages = ['users', 'admins', 'audit', 'mail', 'security'];
const userOpts = { admin: false, fallback: 'memories', pageIds: userPages };
const adminOpts = { admin: true, fallback: 'users', pageIds: adminPages };

{
  const r = parseRoute('#/memories', userOpts);
  assert.equal(r.page, 'memories');
  assert.equal(r.memoryId, null);
}
{
  const id = '8f3c1a2b-4d5e-6789-abcd-ef0123456789';
  const r = parseRoute(`#/memories/${id}`, userOpts);
  assert.equal(r.page, 'memories');
  assert.equal(r.memoryId, id);
}
{
  const r = parseRoute('#/dashboard/memories/abc%2Fdef', userOpts);
  assert.equal(r.page, 'memories');
  assert.equal(r.memoryId, 'abc/def');
}
{
  const r = parseRoute('#/diary', userOpts);
  assert.equal(r.page, 'diary');
  assert.equal(r.memoryId, null);
}
{
  const r = parseRoute('#/nope/whatever', userOpts);
  assert.equal(r.page, 'memories');
  assert.equal(r.memoryId, null);
}
{
  const r = parseRoute('#/users/someone', adminOpts);
  assert.equal(r.page, 'users');
  assert.equal(r.memoryId, null);
}

assert.equal(pathRestToHash('memories'), '#/memories');
assert.equal(pathRestToHash('memories/uuid-1'), '#/memories/uuid-1');
assert.equal(pathRestToHash('/memories/uuid-1/'), '#/memories/uuid-1');
assert.equal(pathRestToHash(''), '#/');

assert.equal(routeHash('memories', null), '#/memories');
assert.equal(routeHash('memories', 'id-1'), '#/memories/id-1');
assert.equal(routeHash('diary', 'ignored'), '#/diary');

console.log('hash-route.test.mjs ok');
