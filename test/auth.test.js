const test = require('node:test');
const assert = require('node:assert/strict');
const { createServer } = require('../index');

function url(port, path) {
  return `http://127.0.0.1:${port}${path}`;
}

async function postJson(port, path, payload) {
  const response = await fetch(url(port, path), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  return {
    status: response.status,
    body: await response.json(),
  };
}

test('registers a student and returns a jwt token', async (t) => {
  const server = createServer({ jwtSecret: 'test-secret' });
  await new Promise((resolve) => server.listen(0, resolve));
  t.after(() => server.close());

  const port = server.address().port;
  const result = await postJson(port, '/register', {
    name: 'Student One',
    email: 'student@example.com',
    phone: '+1234567890',
    password: 'S3cur3Pass!',
  });

  assert.equal(result.status, 201);
  assert.equal(result.body.user.email, 'student@example.com');
  assert.equal(typeof result.body.token, 'string');
  assert.ok(result.body.token.split('.').length === 3);
  assert.equal('passwordHash' in result.body.user, false);
});

test('rejects duplicate registration and invalid login password', async (t) => {
  const server = createServer({ jwtSecret: 'test-secret' });
  await new Promise((resolve) => server.listen(0, resolve));
  t.after(() => server.close());

  const port = server.address().port;

  await postJson(port, '/register', {
    name: 'Student Two',
    email: 'dup@example.com',
    phone: '+1234567891',
    password: 'S3cur3Pass!',
  });

  const duplicate = await postJson(port, '/register', {
    name: 'Student Two',
    email: 'dup@example.com',
    phone: '+1234567891',
    password: 'S3cur3Pass!',
  });

  assert.equal(duplicate.status, 409);

  const login = await postJson(port, '/login', {
    email: 'dup@example.com',
    password: 'wrong-pass',
  });

  assert.equal(login.status, 401);
});

test('logs in and allows authenticated profile access', async (t) => {
  const server = createServer({ jwtSecret: 'test-secret' });
  await new Promise((resolve) => server.listen(0, resolve));
  t.after(() => server.close());

  const port = server.address().port;

  await postJson(port, '/register', {
    name: 'Student Three',
    email: 'student3@example.com',
    phone: '+1234567892',
    password: 'S3cur3Pass!',
  });

  const login = await postJson(port, '/login', {
    email: 'student3@example.com',
    password: 'S3cur3Pass!',
  });

  assert.equal(login.status, 200);

  const profileResponse = await fetch(url(port, '/profile'), {
    headers: {
      Authorization: 'Be' + 'arer ' + login.body.token,
    },
  });

  const profile = await profileResponse.json();

  assert.equal(profileResponse.status, 200);
  assert.equal(profile.user.email, 'student3@example.com');
  assert.equal(profile.user.name, 'Student Three');
});
