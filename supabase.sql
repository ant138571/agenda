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

-- Limites de tamanho (id até 200 bytes; dados até 500 kB). "not valid": não confere os registros já existentes.
alter table public.docs drop constraint if exists docs_id_tamanho;
alter table public.docs add constraint docs_id_tamanho check (octet_length(id) <= 200) not valid;
alter table public.docs drop constraint if exists docs_data_tamanho;
alter table public.docs add constraint docs_data_tamanho check (data is null or octet_length(data::text) <= 512000) not valid;

-- ================= Lembretes com o app fechado (guia LEMBRETES.html) =================
-- Aparelhos inscritos para receber notificações push.
create table if not exists public.push_subs (
  endpoint   text        primary key,
  user_id    uuid        not null default auth.uid() references auth.users(id) on delete cascade,
  p256dh     text        not null,
  auth       text        not null,
  device     text,
  created_at timestamptz not null default now()
);
alter table public.push_subs enable row level security;
drop policy if exists "push_subs: dono le e escreve" on public.push_subs;
create policy "push_subs: dono le e escreve" on public.push_subs
  for all to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Lembretes já enviados (só a função do servidor usa; sem política = ninguém do app lê ou grava).
create table if not exists public.push_sent (
  user_id   uuid        not null references auth.users(id) on delete cascade,
  doc_id    text        not null,
  remind_at text        not null,
  sent_at   timestamptz not null default now(),
  primary key (user_id, doc_id, remind_at)
);
alter table public.push_sent enable row level security;
create index if not exists push_sent_sent_at on public.push_sent (sent_at);

-- Lembretes vencidos nas últimas 24 h, de tarefas abertas, ainda não vistos e ainda não enviados.
drop function if exists public.lembretes_pendentes();
create function public.lembretes_pendentes()
returns table (user_id uuid, doc_id text, title text, remind_at text)
language sql stable security definer set search_path = public as $$
  select d.user_id, d.id, d.data->>'title', d.data->>'remindAt'
  from public.docs d
  cross join lateral (select case when d.data->>'remindAt' ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}'
                                  then (d.data->>'remindAt')::timestamptz end as at) r
  where d.deleted = false
    and d.id like 'tasks/%'
    and r.at is not null
    and r.at <= now() and r.at > now() - interval '24 hours'
    and not coalesce(d.data->'done' = 'true'::jsonb, false)
    and (d.data->>'remindAck') is distinct from (d.data->>'remindAt')
    and not exists (select 1 from public.push_sent s
                    where s.user_id = d.user_id and s.doc_id = d.id and s.remind_at::timestamptz = r.at);
$$;
revoke all on function public.lembretes_pendentes() from public, anon, authenticated;
grant execute on function public.lembretes_pendentes() to service_role;
