// DELIBERATELY INSECURE demo for ai-security-atlas. Do not copy this code.
const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");
const cors = require("cors");

const app = express();
app.use(cors({ origin: "*" })); // VIBE052

// VIBE035: the service-role key ends up in every visitor's browser
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;

app.get("/run", (req, res) => {
  exec(`convert ${req.query.file} out.png`); // VIBE032
  res.send(eval(req.query.expr)); // VIBE030
});

app.get("/search", async (req, res) => {
  const rows = await db.query(`SELECT * FROM posts WHERE title LIKE '%${req.query.q}%'`); // VIBE033
  res.json(rows);
});

function renderComment(el, comment) {
  el.innerHTML = comment.body; // VIBE031
}

const sessionToken = Math.random().toString(36).slice(2); // VIBE050
const agent = new (require("https").Agent)({ rejectUnauthorized: false }); // VIBE034
const digest = crypto.createHash("md5").update("x").digest("hex"); // PQC001
const alice = crypto.createECDH("prime256v1"); // PQC011

app.listen(3000);
