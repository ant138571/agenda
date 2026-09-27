-- Agenda de Tarefas: tabela de sincronização
-- Cole tudo no Supabase em "SQL Editor" > "New query" e clique em "Run".

create table if not exists public.docs (
  user_id    uuid        not null default auth.uid() references auth.users(id) on delete cascade,
  id         text        not null,
  data       jsonb,
  deleted    boolean     not null default false,
  updated_at timestamptz not null default now(),
  primary key (user_id, id)
);

create index if not exists docs_user_updated on public.docs (user_id, updated_at);

-- Cada pessoa só vê e altera as próprias tarefas.
alter table public.docs enable row level security;

drop policy if exists "docs: dono le e escreve" on public.docs;
create policy "docs: dono le e escreve" on public.docs
  for all to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- A data de alteração é sempre a do servidor (garante a sincronização entre aparelhos).
create or replace function public.docs_touch() returns trigger
language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists docs_touch on public.docs;
create trigger docs_touch before insert or update on public.docs
  for each row execute function public.docs_touch();
