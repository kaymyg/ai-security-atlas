// Server-side JavaScript patterns. Labels describe the truth about each line.
const { exec, execFile } = require("child_process");
const https = require("https");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const cors = require("cors");

function dynamic(req, body) {
  eval(req.query.code); // expect[VIBE030]
  const fn = new Function("a", "b", body); // expect[VIBE030]
  const data = JSON.parse(req.body); // safe[VIBE030]
  setTimeout("refreshAll()", 100); // expect[VIBE030] string argument is evaluated as code
  return [fn, data];
}

function shell(branch, file) {
  exec(`git log ${branch}`); // expect[VIBE032]
  exec("convert " + file); // expect[VIBE032]
  exec("ls -la"); // safe[VIBE032]
  execFile("git", ["log", branch]); // safe[VIBE032]
}

async function sql(db, prisma, knex, sqlTag, id, name, q) {
  await db.query(`SELECT * FROM users WHERE id = ${id}`); // expect[VIBE033]
  await prisma.$queryRawUnsafe(q); // expect[VIBE033]
  await knex.raw(`DELETE FROM t WHERE id = ${id}`); // expect[VIBE033]
  await db.query("SELECT * FROM t WHERE name = '" + name + "'"); // expect[VIBE033] plain string concatenation
  await db.query("SELECT * FROM users WHERE id = $1", [id]); // safe[VIBE033]
  await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`; // safe[VIBE033] tagged template binds values
  await sqlTag`SELECT * FROM users WHERE id = ${id}`; // safe[VIBE033]
}

function transport() {
  const insecure = new https.Agent({ rejectUnauthorized: false }); // expect[VIBE034]
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // expect[VIBE034]
  const fine = new https.Agent({ rejectUnauthorized: true }); // safe[VIBE034]
  return [insecure, fine];
}

function randomness() {
  const sessionId = Math.random().toString(36).slice(2); // expect[VIBE050]
  const jitterMs = Math.random() * 100; // safe[VIBE050] not a secret
  const token = crypto.randomUUID(); // safe[VIBE050]
  return [sessionId, jitterMs, token];
}

function web(app, res, token, key) {
  app.use(cors({ origin: "*" })); // expect[VIBE052]
  res.setHeader("Access-Control-Allow-Origin", "*"); // expect[VIBE052]
  app.use(cors()); // expect[VIBE052] cors() with no options allows every origin
  app.use(cors({ origin: ["https://app.example.com"] })); // safe[VIBE052]
  jwt.verify(token, key, { algorithms: ["none"] }); // expect[VIBE051]
  jwt.verify(token, key, { algorithms: ["HS256"] }); // safe[VIBE051]
  if (jwt.decode(token).role === "admin") grantAdmin(); // miss[VIBE051] decode() never checks the signature
  return true;
}

const securityConfig = { csrf: false }; // expect[VIBE053]
const strictConfig = { csrf: true }; // safe[VIBE053]

// FIXME: rate limit the login endpoint  expect[VIBE054]
// TODO: tidy up these helpers  safe[VIBE054]
module.exports = { dynamic, shell, sql, transport, randomness, web, securityConfig };
