-- =====================================================================
--  DeynDhowr · Supabase schema
--  Ku shub dhammaan: Supabase → SQL Editor → New query → Paste → Run
--  Waa ammaan in mar kale la shubo (idempotent).
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------- Tables ----------------------------------------------------

create table if not exists public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

create table if not exists public.app_settings (
  key   text primary key,
  value jsonb not null
);

insert into public.app_settings(key, value) values
  ('payment',    '{"zaad":"","edahab":"","name":"DeynDhowr"}'),
  ('plans',      '[{"months":1,"price":3},{"months":3,"price":9},{"months":6,"price":17},{"months":12,"price":30}]'),
  ('trial_days', '14')
on conflict (key) do nothing;

create table if not exists public.shops (
  id         uuid primary key default gen_random_uuid(),
  name       text not null check (length(name) between 1 and 80),
  phone      text not null default '',
  owner      uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  trial_ends timestamptz not null,
  paid_until timestamptz,
  suspended  boolean not null default false
);
alter table public.shops add column if not exists kind text not null default 'shop';
alter table public.shops add column if not exists logo text;
alter table public.shops add column if not exists logo_v bigint not null default 0;
do $$ begin
  alter table public.shops add constraint shops_kind_chk check (kind in ('shop','whole','pharm','other'));
exception when duplicate_object then null; end $$;

create table if not exists public.members (
  shop_id    uuid not null references public.shops(id) on delete cascade,
  user_id    uuid not null references auth.users(id) on delete cascade,
  role       text not null check (role in ('owner','admin','cash')),
  email      text not null default '',
  name       text not null default '',
  created_at timestamptz not null default now(),
  primary key (shop_id, user_id)
);
create index if not exists members_user_idx on public.members(user_id);

create table if not exists public.invites (
  shop_id    uuid not null references public.shops(id) on delete cascade,
  email      text not null,
  role       text not null check (role in ('admin','cash')),
  name       text not null default '',
  created_at timestamptz not null default now(),
  primary key (shop_id, email)
);

create sequence if not exists public.records_seq;

create table if not exists public.records (
  shop_id    uuid   not null references public.shops(id) on delete cascade,
  kind       text   not null,
  id         text   not null check (length(id) between 1 and 64),
  data       jsonb  not null default '{}'::jsonb,
  u          bigint not null default 0,
  deleted    boolean not null default false,
  seq        bigint not null default nextval('public.records_seq'),
  by_user    uuid,
  updated_at timestamptz not null default now(),
  primary key (shop_id, kind, id)
);
create index if not exists records_shop_seq_idx on public.records(shop_id, seq);
-- record kinds: debt, stock, sale, exp, bill (Iga dir), cfg (sarifka, habaynta dukaanka)
alter table public.records drop constraint if exists records_kind_check;
alter table public.records add constraint records_kind_check check (kind in ('debt','stock','sale','exp','bill','cfg'));

create table if not exists public.payments (
  id          uuid primary key default gen_random_uuid(),
  shop_id     uuid not null references public.shops(id) on delete cascade,
  months      int  not null check (months between 1 and 24),
  amount      numeric(10,2) not null default 0,
  method      text not null default '',
  sender      text not null default '',
  ref         text not null default '',
  status      text not null default 'pending' check (status in ('pending','approved','rejected')),
  note        text not null default '',
  created_by  uuid,
  created_at  timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by uuid
);
create index if not exists payments_shop_idx on public.payments(shop_id, created_at desc);

-- ---------- Row Level Security --------------------------------------
-- Dhammaan qorista waxay maraysaa functions-ka hoose (security definer),
-- kuwaas oo hubinaya xubinnimada, doorka iyo muddaysiga.

alter table public.admins       enable row level security;
alter table public.app_settings enable row level security;
alter table public.shops        enable row level security;
alter table public.members      enable row level security;
alter table public.invites      enable row level security;
alter table public.records      enable row level security;
alter table public.payments     enable row level security;

-- ---------- Helper functions ----------------------------------------

create or replace function public.my_email() returns text
language sql stable as $$
  select lower(coalesce(auth.jwt() ->> 'email', ''))
$$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from admins where user_id = auth.uid())
$$;

create or replace function public.my_role(p_shop uuid) returns text
language sql stable security definer set search_path = public as $$
  select role from members where shop_id = p_shop and user_id = auth.uid()
$$;

create or replace function public.is_member(p_shop uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from members where shop_id = p_shop and user_id = auth.uid())
$$;

create or replace function public.shop_active(p_shop uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select not s.suspended
                      and greatest(s.trial_ends, coalesce(s.paid_until, '-infinity'::timestamptz)) > now()
                   from shops s where s.id = p_shop), false)
$$;

-- Realtime: xubnaha dukaanka ayaa keliya arka isbeddellada records-ka
drop policy if exists records_member_select on public.records;
create policy records_member_select on public.records
  for select to authenticated using (public.is_member(shop_id));

-- ---------- App RPCs -------------------------------------------------

create or replace function public.get_config() returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_object_agg(key, value) from app_settings
$$;

create or replace function public.claim_invites() returns int
language plpgsql security definer set search_path = public as $$
declare n int := 0; e text := my_email();
begin
  if auth.uid() is null or e = '' then return 0; end if;
  insert into members(shop_id, user_id, role, email, name)
    select i.shop_id, auth.uid(), i.role, e, i.name from invites i where lower(i.email) = e
  on conflict (shop_id, user_id) do nothing;
  get diagnostics n = row_count;
  delete from invites where lower(email) = e;
  return n;
end $$;

drop function if exists public.shop_row(uuid);
create or replace function public.shop_row(p_shop uuid)
returns table(id uuid, name text, phone text, kind text, role text, trial_ends timestamptz, paid_until timestamptz,
              suspended boolean, active boolean, pending boolean, ends timestamptz, logo_v bigint)
language sql stable security definer set search_path = public as $$
  select s.id, s.name, s.phone, s.kind, m.role, s.trial_ends, s.paid_until, s.suspended,
         shop_active(s.id),
         exists (select 1 from payments p where p.shop_id = s.id and p.status = 'pending'),
         greatest(s.trial_ends, coalesce(s.paid_until, '-infinity'::timestamptz)),
         s.logo_v
  from shops s join members m on m.shop_id = s.id and m.user_id = auth.uid()
  where p_shop is null or s.id = p_shop
  order by s.created_at
$$;

drop function if exists public.create_shop(text, text);
create or replace function public.create_shop(p_name text, p_phone text default '', p_kind text default 'shop') returns uuid
language plpgsql security definer set search_path = public as $$
declare sid uuid; td int;
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  if coalesce(trim(p_name), '') = '' then raise exception 'name_required'; end if;
  if (select count(*) from shops where owner = auth.uid()) >= 3 then raise exception 'too_many_shops'; end if;
  select coalesce((value #>> '{}')::int, 14) into td from app_settings where key = 'trial_days';
  insert into shops(name, phone, kind, owner, trial_ends)
    values (trim(p_name), coalesce(trim(p_phone), ''),
            case when p_kind in ('shop','whole','pharm','other') then p_kind else 'shop' end,
            auth.uid(), now() + make_interval(days => coalesce(td, 14)))
    returning id into sid;
  insert into members(shop_id, user_id, role, email) values (sid, auth.uid(), 'owner', my_email());
  return sid;
end $$;

drop function if exists public.update_shop(uuid, text, text);
create or replace function public.update_shop(p_shop uuid, p_name text, p_phone text, p_kind text default null) returns void
language plpgsql security definer set search_path = public as $$
begin
  if coalesce(my_role(p_shop), '') not in ('owner','admin') then raise exception 'forbidden'; end if;
  if coalesce(trim(p_name), '') = '' then raise exception 'name_required'; end if;
  update shops set name = trim(p_name), phone = coalesce(trim(p_phone), ''),
         kind = case when p_kind in ('shop','whole','pharm','other') then p_kind else kind end
    where id = p_shop;
end $$;

-- Logada meheradda (sawir yar oo data:image ah, ugu badnaan ~110 KB)
create or replace function public.shop_logo(p_shop uuid) returns text
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_member(p_shop) and not is_admin() then raise exception 'forbidden'; end if;
  return (select logo from shops where id = p_shop);
end $$;

create or replace function public.set_shop_logo(p_shop uuid, p_logo text) returns bigint
language plpgsql security definer set search_path = public as $$
declare v bigint := (extract(epoch from clock_timestamp()) * 1000)::bigint;
begin
  if coalesce(my_role(p_shop), '') not in ('owner','admin') then raise exception 'forbidden'; end if;
  if p_logo is not null and (p_logo !~ '^data:image/(png|jpeg|webp);base64,' or length(p_logo) > 150000) then
    raise exception 'bad_logo';
  end if;
  update shops set logo = p_logo, logo_v = case when p_logo is null then 0 else v end where id = p_shop;
  return case when p_logo is null then 0 else v end;
end $$;

create or replace function public.shop_members(p_shop uuid)
returns table(user_id uuid, email text, name text, role text, pending boolean)
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_member(p_shop) then raise exception 'forbidden'; end if;
  return query
    select m.user_id, m.email, m.name, m.role, false from members m where m.shop_id = p_shop
    union all
    select null::uuid, i.email, i.name, i.role, true from invites i where i.shop_id = p_shop
    order by 5, 4 desc;
end $$;

create or replace function public.invite_member(p_shop uuid, p_email text, p_role text, p_name text default '')
returns text language plpgsql security definer set search_path = public as $$
declare r text := my_role(p_shop); e text := lower(trim(p_email)); uid uuid;
begin
  if coalesce(r, '') not in ('owner','admin') then raise exception 'forbidden'; end if;
  if p_role not in ('admin','cash') then raise exception 'bad_role'; end if;
  if r = 'admin' and p_role = 'admin' then raise exception 'forbidden'; end if;
  if e !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then raise exception 'bad_email'; end if;
  if (select count(*) from members where shop_id = p_shop) + (select count(*) from invites where shop_id = p_shop) >= 25
    then raise exception 'too_many_members'; end if;
  select id into uid from auth.users where lower(email) = e;
  if uid is not null then
    insert into members(shop_id, user_id, role, email, name) values (p_shop, uid, p_role, e, coalesce(p_name, ''))
    on conflict (shop_id, user_id) do update set role = excluded.role
      where members.role <> 'owner';
    return 'added';
  end if;
  insert into invites(shop_id, email, role, name) values (p_shop, e, p_role, coalesce(p_name, ''))
  on conflict (shop_id, email) do update set role = excluded.role, name = excluded.name;
  return 'invited';
end $$;

create or replace function public.remove_member(p_shop uuid, p_email text) returns void
language plpgsql security definer set search_path = public as $$
declare r text := my_role(p_shop); e text := lower(trim(p_email)); tr text;
begin
  if coalesce(r, '') not in ('owner','admin') then raise exception 'forbidden'; end if;
  delete from invites where shop_id = p_shop and lower(email) = e;
  select role into tr from members where shop_id = p_shop and lower(email) = e;
  if tr is null then return; end if;
  if tr = 'owner' then raise exception 'cannot_remove_owner'; end if;
  if r = 'admin' and tr = 'admin' then raise exception 'forbidden'; end if;
  delete from members where shop_id = p_shop and lower(email) = e;
end $$;

create or replace function public.leave_shop(p_shop uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if my_role(p_shop) = 'owner' then raise exception 'owner_cannot_leave'; end if;
  delete from members where shop_id = p_shop and user_id = auth.uid();
end $$;

-- Sync: client pushes changed rows; newer "u" (client ms timestamp) wins.
create or replace function public.sync_push(p_shop uuid, p_rows jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare r text := my_role(p_shop); x jsonb; n int := 0; skipped int := 0; c int;
begin
  if r is null then raise exception 'forbidden'; end if;
  if not shop_active(p_shop) then raise exception 'subscription_inactive'; end if;
  if jsonb_typeof(p_rows) <> 'array' or jsonb_array_length(p_rows) > 500 then raise exception 'bad_rows'; end if;
  for x in select * from jsonb_array_elements(p_rows) loop
    if r = 'cash' and coalesce((x->>'deleted')::boolean, false) then skipped := skipped + 1; continue; end if;
    if length((x->'data')::text) > 200000 then skipped := skipped + 1; continue; end if;
    if coalesce(x->>'kind','') not in ('debt','stock','sale','exp','bill','cfg') then skipped := skipped + 1; continue; end if;
    insert into records(shop_id, kind, id, data, u, deleted, by_user, updated_at)
      values (p_shop, x->>'kind', x->>'id', coalesce(x->'data', '{}'::jsonb), coalesce((x->>'u')::bigint, 0),
              coalesce((x->>'deleted')::boolean, false), auth.uid(), now())
    on conflict (shop_id, kind, id) do update
      set data = excluded.data, u = excluded.u, deleted = excluded.deleted,
          seq = nextval('public.records_seq'), by_user = excluded.by_user, updated_at = now()
      where records.u <= excluded.u;
    get diagnostics c = row_count; n := n + c;
  end loop;
  return jsonb_build_object('written', n, 'skipped', skipped);
end $$;

create or replace function public.sync_pull(p_shop uuid, p_since bigint, p_limit int default 1000)
returns table(kind text, id text, data jsonb, u bigint, deleted boolean, seq bigint)
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_member(p_shop) then raise exception 'forbidden'; end if;
  return query
    select r.kind, r.id, r.data, r.u, r.deleted, r.seq from records r
    where r.shop_id = p_shop and r.seq > coalesce(p_since, 0)
    order by r.seq limit least(greatest(coalesce(p_limit, 1000), 1), 2000);
end $$;

create or replace function public.submit_payment(p_shop uuid, p_months int, p_method text, p_sender text, p_ref text)
returns uuid language plpgsql security definer set search_path = public as $$
declare pid uuid; price numeric;
begin
  if coalesce(my_role(p_shop), '') not in ('owner','admin') then raise exception 'forbidden'; end if;
  if coalesce(trim(p_ref), '') = '' and coalesce(trim(p_sender), '') = '' then raise exception 'ref_required'; end if;
  select (p->>'price')::numeric into price
    from app_settings s, jsonb_array_elements(s.value) p
    where s.key = 'plans' and (p->>'months')::int = p_months;
  if price is null then raise exception 'bad_plan'; end if;
  update payments set months = p_months, amount = price, method = coalesce(p_method, ''),
         sender = coalesce(trim(p_sender), ''), ref = coalesce(trim(p_ref), ''), created_at = now(), created_by = auth.uid()
    where shop_id = p_shop and status = 'pending' returning id into pid;
  if pid is null then
    insert into payments(shop_id, months, amount, method, sender, ref, created_by)
      values (p_shop, p_months, price, coalesce(p_method, ''), coalesce(trim(p_sender), ''), coalesce(trim(p_ref), ''), auth.uid())
      returning id into pid;
  end if;
  return pid;
end $$;

create or replace function public.shop_payments(p_shop uuid)
returns table(id uuid, months int, amount numeric, method text, ref text, status text, note text, created_at timestamptz)
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_member(p_shop) then raise exception 'forbidden'; end if;
  return query select p.id, p.months, p.amount, p.method, p.ref, p.status, p.note, p.created_at
    from payments p where p.shop_id = p_shop order by p.created_at desc limit 20;
end $$;

-- ---------- Admin RPCs (adiga keliya) --------------------------------

drop function if exists public.admin_overview();
create or replace function public.admin_overview()
returns table(id uuid, name text, phone text, kind text, owner_email text, created_at timestamptz, trial_ends timestamptz,
              paid_until timestamptz, suspended boolean, active boolean, members bigint, records bigint,
              last_activity timestamptz, pending bigint)
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  return query
    select s.id, s.name, s.phone, s.kind, u.email::text, s.created_at, s.trial_ends, s.paid_until, s.suspended,
           shop_active(s.id),
           (select count(*) from members m where m.shop_id = s.id),
           (select count(*) from records r where r.shop_id = s.id and not r.deleted),
           (select max(r.updated_at) from records r where r.shop_id = s.id),
           (select count(*) from payments p where p.shop_id = s.id and p.status = 'pending')
    from shops s left join auth.users u on u.id = s.owner
    order by s.created_at desc;
end $$;

create or replace function public.admin_payments(p_status text default 'pending')
returns table(id uuid, shop_id uuid, shop_name text, months int, amount numeric, method text, sender text, ref text,
              status text, note text, created_at timestamptz)
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  return query
    select p.id, p.shop_id, s.name, p.months, p.amount, p.method, p.sender, p.ref, p.status, p.note, p.created_at
    from payments p join shops s on s.id = p.shop_id
    where p_status is null or p_status = '' or p.status = p_status
    order by p.created_at desc limit 300;
end $$;

create or replace function public.admin_review(p_id uuid, p_approve boolean, p_note text default '') returns void
language plpgsql security definer set search_path = public as $$
declare p payments%rowtype;
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  select * into p from payments where id = p_id for update;
  if p.id is null or p.status <> 'pending' then raise exception 'not_pending'; end if;
  update payments set status = case when p_approve then 'approved' else 'rejected' end,
         note = coalesce(p_note, ''), reviewed_at = now(), reviewed_by = auth.uid() where id = p_id;
  if p_approve then
    update shops set paid_until = greatest(now(), trial_ends, coalesce(paid_until, '-infinity'::timestamptz))
                                  + make_interval(months => p.months)
      where id = p.shop_id;
  end if;
end $$;

create or replace function public.admin_extend(p_shop uuid, p_days int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  update shops set paid_until = greatest(now(), trial_ends, coalesce(paid_until, '-infinity'::timestamptz))
                                + make_interval(days => p_days)
    where id = p_shop;
end $$;

create or replace function public.admin_suspend(p_shop uuid, p_suspend boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  update shops set suspended = p_suspend where id = p_shop;
end $$;

create or replace function public.admin_set_setting(p_key text, p_value jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  if p_key not in ('payment','plans','trial_days') then raise exception 'bad_key'; end if;
  insert into app_settings(key, value) values (p_key, p_value)
  on conflict (key) do update set value = excluded.value;
end $$;

-- ---------- Permissions ---------------------------------------------

revoke all on all functions in schema public from public, anon;
grant execute on all functions in schema public to authenticated;
revoke all on all tables in schema public from anon;
grant select on public.records to authenticated;

-- ---------- Realtime ------------------------------------------------
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'records') then
    execute 'alter publication supabase_realtime add table public.records';
  end if;
end $$;

-- =====================================================================
--  KA DIB: is admin ka dhig (beddel email-ka kan, kadib Run):
--  insert into public.admins(user_id)
--    select id from auth.users where lower(email) = lower('EMAILKAAGA@gmail.com')
--  on conflict do nothing;
-- =====================================================================
