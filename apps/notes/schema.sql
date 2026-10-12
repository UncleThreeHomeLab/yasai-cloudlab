CREATE TABLE IF NOT EXISTS public.notes (
    id text PRIMARY KEY,
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
    body text NOT NULL CHECK (length(body) BETWEEN 1 AND 8192),
    attachment_key text NOT NULL
);
