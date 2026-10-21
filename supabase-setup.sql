-- Ejecuta esto en Supabase: panel de tu proyecto -> SQL Editor -> New query -> pegar y "Run"

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

-- Después de ejecutar esto, ve a Storage (menú lateral) -> "New bucket"
-- Nombre: images
-- Marca la opción "Public bucket" para que las fotos se puedan ver desde la app.
