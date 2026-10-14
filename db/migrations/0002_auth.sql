-- Sessions, invites and notification preferences.
-- Magic-link and session tokens are stored only as hashes.

create table if not exists magic_links (
  id uuid primary key,
  email text not null,
  token_hash text not null unique,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists sessions (
  id uuid primary key,
  user_id uuid not null references users (id),
  token_hash text not null unique,
  expires_at timestamptz not null,
  active_tenant_id uuid references tenants (id),
  created_at timestamptz not null default now()
);

create table if not exists invites (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  email text not null,
  role text not null check (role in ('owner', 'member', 'credential_viewer', 'analyst')),
  invited_by uuid,
  created_at timestamptz not null default now()
);

create table if not exists notification_preferences (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  user_id uuid not null references users (id),
  mode text not null check (mode in ('immediate', 'digest', 'off')),
  unique (tenant_id, user_id)
);

create table if not exists legitimate_domains (
  id uuid primary key,
  tenant_id uuid not null references tenants (id),
  domain text not null,
  finding_id uuid references findings (id),
  created_at timestamptz not null default now(),
  unique (tenant_id, domain)
);

alter table invites enable row level security;
alter table invites force row level security;
drop policy if exists tenant_isolation on invites;
create policy tenant_isolation on invites
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table notification_preferences enable row level security;
alter table notification_preferences force row level security;
drop policy if exists tenant_isolation on notification_preferences;
create policy tenant_isolation on notification_preferences
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

alter table legitimate_domains enable row level security;
alter table legitimate_domains force row level security;
drop policy if exists tenant_isolation on legitimate_domains;
create policy tenant_isolation on legitimate_domains
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

grant select, insert, update, delete on magic_links, sessions, invites, notification_preferences, legitimate_domains to cti_app;
