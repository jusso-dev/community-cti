-- Sign-in, invites, notifications, credential exposure and product events.

create table if not exists magic_links (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  token_hash text not null unique,
  expires_at timestamptz not null,
  consumed_at timestamptz
);

create table if not exists sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id),
  tenant_id uuid references tenants(id),
  token_hash text not null unique,
  expires_at timestamptz not null
);

create table if not exists invites (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  email text not null,
  role text not null check (role in ('owner', 'member', 'credential_viewer', 'analyst')),
  created_by uuid not null,
  created_at timestamptz not null default now()
);

create table if not exists notification_preferences (
  tenant_id uuid not null references tenants(id),
  user_id uuid not null references users(id),
  mode text not null check (mode in ('immediate', 'digest', 'off')) default 'immediate',
  primary key (tenant_id, user_id)
);

create table if not exists legitimate_domains (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  domain text not null,
  created_at timestamptz not null default now(),
  unique (tenant_id, domain)
);

create table if not exists credential_exposures (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  domain_name text not null,
  email_ciphertext text not null,
  breach_name text not null,
  breach_date date,
  data_classes text[] not null default '{}',
  finding_id uuid references findings(id),
  resolved_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists product_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  user_id uuid,
  name text not null check (name in ('finding_viewed', 'finding_actioned', 'finding_dismissed')),
  finding_id uuid,
  at timestamptz not null default now()
);

create or replace function create_organisation(p_user_id uuid, p_name text, p_type text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  tid uuid;
begin
  if p_type not in ('acco', 'land_council', 'ams', 'indigenous_corporation', 'other') then
    raise exception 'invalid organisation type';
  end if;
  insert into tenants (name, type) values (p_name, p_type) returning id into tid;
  insert into memberships (tenant_id, user_id, role) values (tid, p_user_id, 'owner');
  update sessions set tenant_id = tid
    where user_id = p_user_id and expires_at > now() and tenant_id is null;
  return tid;
end $$;

revoke all on function create_organisation(uuid, text, text) from public;
grant execute on function create_organisation(uuid, text, text) to cti_app;

do $$
declare
  t text;
begin
  foreach t in array array['invites', 'notification_preferences', 'legitimate_domains', 'credential_exposures', 'product_events']
  loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format('drop policy if exists tenant_isolation on %I', t);
    execute format(
      'create policy tenant_isolation on %I using (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid) with check (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)',
      t
    );
  end loop;
end $$;

grant select, insert, update, delete on all tables in schema public to cti_app;
revoke update, delete on audit_log from cti_app;
grant select, insert on audit_log to cti_app;
revoke all on schema_migrations from cti_app;
