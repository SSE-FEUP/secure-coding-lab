import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { db, query, run } from "./db.js";
import morgan from "morgan";
import cors from "cors";
import fs from "fs/promises";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));


app.use(cors());

const DEBUG = String(process.env.DEBUG ?? "true").toLowerCase() === "true";


async function requireAuth(req, res, next) {
  const name = req.header("X-User");
  if (!name) return res.status(401).json({ error: "not authenticated" });

  const rows = await query(
    "SELECT id, name, role FROM users WHERE name = ?",
    [name]
  );

  if (rows.length === 0) return res.status(401).json({ error: "not authenticated" });

  req.user = rows[0];
  next();
}

app.get("/users", async (req, res, next) => {
  try {
    const name = req.query.name || "";

    const sql = `SELECT id, name, role FROM users WHERE name = '${name}'`;

    const rows = await query(sql);
    res.json(rows);
  } catch (e) {
    next(e);
  }
});


app.get("/search", async (req, res, next) => {
  try {
    const q = req.query.q || "";

    const rows = await query(
      "SELECT name FROM users WHERE name LIKE ?",
      [`%${q}%`]
    );

    const list = rows.map((r) => `<li>${r.name}</li>`).join("");

    const tpl = await fs.readFile(path.join(__dirname, "views/result.html"), "utf8");

    const html = tpl
      .replace("__QUERY__", q)
      .replace("__ROWS__", `<ul>${list}</ul>`);

    res.type("html").send(html);
  } catch (e) {
    next(e);
  }
});


app.post("/admin/deleteUser", requireAuth, async (req, res, next) => {
  try {
    const targetId = Number(req.body.userId);
    if (!Number.isInteger(targetId)) {
      return res.status(400).json({ error: "bad input" });
    }

    await run("DELETE FROM users WHERE id = ?", [targetId]);

    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

app.post("/login", async (req, res, next) => {
  try {
    
    console.log("Login attempt", req.body);

    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: "missing credentials" });
    }

    
    const rows = await query(
      "SELECT id, name, role FROM users WHERE name = ? AND password = ?",
      [username, password]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: "invalid credentials" });
    }

    res.json({ ok: true, user: rows[0].name });
  } catch (err) {
    
    if (DEBUG) {
      return res.status(500).type("text").send(err.stack);
    }
    next(err);
  }
});

app.get("/", (req, res) => {
  res.type("text").send(
    [
      "Lab server running.",
      "",
      "Try routes:",
      "  GET  /users?name=<term>            (look at how SQL is built)",
      "  GET  /search?q=<term>              (look at how HTML is built)",
      "  POST /admin/deleteUser             (JSON {userId}, header X-User: alice or bob)",
      "  POST /login                        (JSON {username, password})",
      "",
      "Goal: find 5 security issues in the code.",
    ].join("\n")
  );
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "internal error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Lab listening on http://localhost:${PORT}`);
});
