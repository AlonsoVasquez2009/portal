-- Ejecuta esto en Neon: SQL Editor (o con psql "$DATABASE_URL" -f schema.sql)
CREATE EXTENSION IF NOT EXISTS citext;   -- correos sin distinguir mayúsculas

CREATE TABLE IF NOT EXISTS usuarios (
  id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  nombre         TEXT        NOT NULL CHECK (length(nombre) BETWEEN 1 AND 80),
  correo         CITEXT      NOT NULL UNIQUE,
  hash_password  TEXT        NOT NULL,          -- bcrypt, nunca la contraseña real
  creado_en      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS progreso (
  usuario_id     BIGINT      NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  leccion        TEXT        NOT NULL,          -- ej. 'prog0', 'red2' (ruta + índice)
  completada_en  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (usuario_id, leccion)
);

CREATE INDEX IF NOT EXISTS idx_progreso_usuario ON progreso(usuario_id);
