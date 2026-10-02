import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { OAuth2Client } from "google-auth-library";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const SECRET = process.env.JWT_SECRET;
if (!SECRET || !process.env.DATABASE_URL) throw new Error("Faltan DATABASE_URL o JWT_SECRET en .env");

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
if (!process.env.GOOGLE_CLIENT_ID) throw new Error("Falta GOOGLE_CLIENT_ID en .env");

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());

const cookieOpts = {
  httpOnly: true, sameSite: "lax", maxAge: 7 * 24 * 3600 * 1000,
  secure: process.env.NODE_ENV === "production",
};
const emitir = (res, u) =>
  res.cookie("sesion", jwt.sign({ id: u.id }, SECRET, { expiresIn: "7d" }), cookieOpts);
const publico = (u) => ({ nombre: u.nombre, correo: u.correo });

function auth(req, res, next) {
  try { req.uid = jwt.verify(req.cookies.sesion, SECRET).id; next(); }
  catch { res.status(401).json({ error: "Sesión no válida" }); }
}

app.post("/api/registro", async (req, res) => {
  const { nombre = "", correo = "", password = "" } = req.body;
  if (!nombre.trim() || !/^\S+@\S+\.\S+$/.test(correo) || password.length < 8)
    return res.status(400).json({ error: "Datos inválidos (contraseña mínima de 8 caracteres)." });
  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      "INSERT INTO usuarios (nombre, correo, hash_password) VALUES ($1,$2,$3) RETURNING id, nombre, correo",
      [nombre.trim(), correo.trim(), hash]);
    emitir(res, rows[0]);
    res.status(201).json({ usuario: publico(rows[0]) });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Ya existe una cuenta con ese correo." });
    console.error(e); res.status(500).json({ error: "Error del servidor" });
  }
});

app.post("/api/login", async (req, res) => {
  const { correo = "", password = "" } = req.body;
  try {
    const { rows } = await pool.query("SELECT * FROM usuarios WHERE correo = $1", [correo.trim()]);
    const u = rows[0];
    if (!u || !u.hash_password || !(await bcrypt.compare(password, u.hash_password)))
      return res.status(401).json({ error: "Correo o contraseña incorrectos." });
    emitir(res, u);
    res.json({ usuario: publico(u) });
  } catch (e) { console.error(e); res.status(500).json({ error: "Error del servidor" }); }
});

app.post("/api/salir", (_req, res) => { res.clearCookie("sesion", cookieOpts); res.json({ ok: true }); });

app.get("/api/yo", auth, async (req, res) => {
  const { rows } = await pool.query("SELECT nombre, correo FROM usuarios WHERE id = $1", [req.uid]);
  if (!rows[0]) return res.status(401).json({ error: "Sesión no válida" });
  res.json({ usuario: rows[0] });
});

app.get("/api/progreso", auth, async (req, res) => {
  const { rows } = await pool.query("SELECT leccion FROM progreso WHERE usuario_id = $1", [req.uid]);
  res.json({ lecciones: rows.map((r) => r.leccion) });
});

app.put("/api/progreso", auth, async (req, res) => {
  const { leccion, hecha } = req.body;
  if (!/^[a-z]{2,10}\d{1,3}$/.test(leccion || "")) return res.status(400).json({ error: "Lección inválida" });
  if (hecha) await pool.query(
    "INSERT INTO progreso (usuario_id, leccion) VALUES ($1,$2) ON CONFLICT DO NOTHING", [req.uid, leccion]);
  else await pool.query("DELETE FROM progreso WHERE usuario_id = $1 AND leccion = $2", [req.uid, leccion]);
  res.json({ ok: true });
});

app.post("/api/google", async (req, res) => {
  const { credential } = req.body; // id_token que manda el botón de Google
  if (!credential) return res.status(400).json({ error: "Falta credential" });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload.email_verified)
      return res.status(401).json({ error: "Correo de Google no verificado" });

    const { sub: googleId, email, name } = payload;

    // busca por google_id o por correo (por si ya tenía cuenta con password)
    const { rows: existentes } = await pool.query(
      "SELECT * FROM usuarios WHERE google_id = $1 OR correo = $2",
      [googleId, email]
    );

    let usuario;
    if (existentes[0]) {
      usuario = existentes[0];
      if (!usuario.google_id) {
        await pool.query("UPDATE usuarios SET google_id = $1 WHERE id = $2", [googleId, usuario.id]);
      }
    } else {
      const { rows } = await pool.query(
        `INSERT INTO usuarios (nombre, correo, google_id, hash_password)
         VALUES ($1, $2, $3, NULL) RETURNING id, nombre, correo`,
        [name || email.split("@")[0], email, googleId]
      );
      usuario = rows[0];
    }

    emitir(res, usuario);
    res.json({ usuario: publico(usuario) });
  } catch (e) {
    console.error(e);
    res.status(401).json({ error: "Token de Google inválido" });
  }
});

app.use(express.static(path.join(__dirname, "public"), { index: "Portal.html" }));
app.listen(process.env.PORT || 3000, () => console.log("Portal en http://localhost:" + (process.env.PORT || 3000)));