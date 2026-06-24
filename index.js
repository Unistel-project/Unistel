const http = require('http');
const crypto = require('crypto');

const DEFAULT_TOKEN_TTL_SECONDS = 60 * 60;
const MAX_REQUEST_BODY_BYTES = 1_000_000;

function base64UrlEncode(value) {
  return Buffer.from(value)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(value) {
  const padded = value.padEnd(value.length + ((4 - (value.length % 4)) % 4), '=');
  const normalized = padded.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(normalized, 'base64').toString('utf8');
}

function createToken(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${data}.${signature}`;
}

function verifyToken(token, secret) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const [header, payload, signature] = token.split('.');
  if (!header || !payload || !signature) {
    return null;
  }

  const data = `${header}.${payload}`;
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expectedSignature);

  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return null;
  }

  let parsedPayload;
  try {
    parsedPayload = JSON.parse(base64UrlDecode(payload));
  } catch {
    return null;
  }

  if (typeof parsedPayload.exp === 'number' && parsedPayload.exp < Math.floor(Date.now() / 1000)) {
    return null;
  }

  return parsedPayload;
}

function hashPassword(password, salt) {
  const resolvedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, resolvedSalt, 64).toString('hex');
  return `${resolvedSalt}:${hash}`;
}

function verifyPassword(password, hashedPassword) {
  const [salt, storedHash] = String(hashedPassword || '').split(':');
  if (!salt || !storedHash) {
    return false;
  }

  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  const storedBuffer = Buffer.from(storedHash, 'hex');
  const passwordBuffer = Buffer.from(hash, 'hex');

  if (storedBuffer.length !== passwordBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(storedBuffer, passwordBuffer);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let finished = false;

    req.on('data', (chunk) => {
      if (finished) {
        return;
      }

      body += chunk;
      if (body.length > MAX_REQUEST_BODY_BYTES) {
        finished = true;
        reject(new Error('Request body too large'));
        // Stop reading from the socket immediately once the size limit is exceeded.
        req.destroy();
        return;
      }
    });

    req.on('end', () => {
      if (finished) {
        return;
      }

      if (!body) {
        finished = true;
        resolve({});
        return;
      }

      try {
        finished = true;
        resolve(JSON.parse(body));
      } catch {
        finished = true;
        reject(new Error('Invalid JSON body'));
      }
    });

    req.on('error', (error) => {
      if (!finished) {
        finished = true;
        reject(error);
      }
    });
  });
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function sendHtml(res, html) {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function toSafeUser(user) {
  return {
    name: user.name,
    email: user.email,
    phone: user.phone,
  };
}

function buildPage() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Unistel Authentication</title>
  </head>
  <body>
    <h1>Unistel Student Authentication</h1>

    <section>
      <h2>Register</h2>
      <form id="register-form">
        <label>
          Name
          <input name="name" type="text" required />
        </label><br />
        <label>
          Email
          <input name="email" type="email" required />
        </label><br />
        <label>
          Phone
          <input name="phone" type="tel" required />
        </label><br />
        <label>
          Password
          <input name="password" type="password" required />
        </label><br />
        <button type="submit">Create account</button>
      </form>
      <pre id="register-result"></pre>
    </section>

    <section>
      <h2>Login</h2>
      <form id="login-form">
        <label>
          Email
          <input name="email" type="email" required />
        </label><br />
        <label>
          Password
          <input name="password" type="password" required />
        </label><br />
        <button type="submit">Sign in</button>
      </form>
      <pre id="login-result"></pre>
    </section>

    <script>
      async function submitForm(form, url, outputId) {
        const data = Object.fromEntries(new FormData(form).entries());
        const response = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data),
        });

        const payload = await response.json();
        document.getElementById(outputId).textContent = JSON.stringify(payload, null, 2);
      }

      document.getElementById('register-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        await submitForm(event.target, '/register', 'register-result');
      });

      document.getElementById('login-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        await submitForm(event.target, '/login', 'login-result');
      });
    </script>
  </body>
</html>`;
}

function createServer(options = {}) {
  const usersByEmail = new Map();
  const jwtSecret = options.jwtSecret || process.env.JWT_SECRET;
  if (!jwtSecret) {
    throw new Error('JWT secret is required. Set JWT_SECRET or pass jwtSecret in options.');
  }
  const tokenTtl = options.tokenTtlSeconds || DEFAULT_TOKEN_TTL_SECONDS;

  return http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/') {
      sendHtml(res, buildPage());
      return;
    }

    if (req.method === 'POST' && req.url === '/register') {
      try {
        const { name, email, phone, password } = await readJsonBody(req);

        if (!name || !email || !phone || !password) {
          sendJson(res, 400, { error: 'name, email, phone and password are required' });
          return;
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        if (usersByEmail.has(normalizedEmail)) {
          sendJson(res, 409, { error: 'User with this email already exists' });
          return;
        }

        const user = {
          name: String(name).trim(),
          email: normalizedEmail,
          phone: String(phone).trim(),
          passwordHash: hashPassword(String(password)),
        };

        usersByEmail.set(normalizedEmail, user);

        const now = Math.floor(Date.now() / 1000);
        const token = createToken(
          {
            sub: normalizedEmail,
            name: user.name,
            phone: user.phone,
            iat: now,
            exp: now + tokenTtl,
          },
          jwtSecret,
        );

        sendJson(res, 201, {
          message: 'Registration successful',
          token,
          user: toSafeUser(user),
        });
      } catch (error) {
        sendJson(res, 400, { error: error.message });
      }
      return;
    }

    if (req.method === 'POST' && req.url === '/login') {
      try {
        const { email, password } = await readJsonBody(req);

        if (!email || !password) {
          sendJson(res, 400, { error: 'email and password are required' });
          return;
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        const user = usersByEmail.get(normalizedEmail);

        if (!user || !verifyPassword(String(password), user.passwordHash)) {
          sendJson(res, 401, { error: 'Invalid email or password' });
          return;
        }

        const now = Math.floor(Date.now() / 1000);
        const token = createToken(
          {
            sub: normalizedEmail,
            name: user.name,
            phone: user.phone,
            iat: now,
            exp: now + tokenTtl,
          },
          jwtSecret,
        );

        sendJson(res, 200, {
          message: 'Login successful',
          token,
          user: toSafeUser(user),
        });
      } catch (error) {
        sendJson(res, 400, { error: error.message });
      }
      return;
    }

    if (req.method === 'GET' && req.url === '/profile') {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
      const payload = verifyToken(token, jwtSecret);

      if (!payload || !payload.sub) {
        sendJson(res, 401, { error: 'Unauthorized' });
        return;
      }

      const user = usersByEmail.get(String(payload.sub).toLowerCase());
      if (!user) {
        sendJson(res, 404, { error: 'User not found' });
        return;
      }

      sendJson(res, 200, { user: toSafeUser(user) });
      return;
    }

    sendJson(res, 404, { error: 'Not found' });
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  const server = createServer();
  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });
}

module.exports = {
  createServer,
  hashPassword,
  verifyPassword,
  createToken,
  verifyToken,
};
