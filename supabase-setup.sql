-- Ejecuta esto en Supabase: panel de tu proyecto -> SQL Editor -> New query -> pegar y "Run"
-- Se puede ejecutar varias veces sin problema y NO borra las recetas que ya tengas.

create extension if not exists "pgcrypto";

create table if not exists recipes (
  id uuid primary key default gen_random_uuid(),
  titulo text not null,
  ingredientes text[] not null default '{}',
  pasos text[] not null default '{}',
  origen text,
  source_url text,
  video_id text,
  image_url text,
  creado timestamptz default now()
);

-- Columnas añadidas en versiones posteriores (si la tabla ya existía, se añaden aquí):
alter table recipes add column if not exists etiquetas text[] not null default '{}';
alter table recipes add column if not exists categorias text[] not null default '{}';
alter table recipes add column if not exists raciones text;
alter table recipes add column if not exists propietario text;
alter table recipes add column if not exists compartida boolean not null default false;

-- Perfiles de las personas que usan la app
create table if not exists perfiles (
  id uuid primary key default gen_random_uuid(),
  nombre text not null,
  creado timestamptz default now()
);
create unique index if not exists perfiles_nombre_unico on perfiles (lower(nombre));

-- Las recetas que ya tenías guardadas no tienen propietario: las verán todos los perfiles.

-- Después, ve a Storage (menú lateral) -> "New bucket" (solo si aún no lo creaste)
-- Nombre: images
-- Marca la opción "Public bucket" para que las fotos se puedan ver desde la app.
