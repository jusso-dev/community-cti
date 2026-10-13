-- Agents, cost, sharing and integrations. Sharing tables exist so the controls can be tested.
-- Publishing shared intelligence stays switched off until governance endorsement. See issue 42.

create table if not exists agent_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  role text not null,
  model text not null,
  tokens_in integer not null,
  tokens_out integer not null,
  cost_aud numeric(12, 4) not null,
  duration_ms integer not null,
  output_hash text not null,
  status text not null check (status in ('ok', 'rejected', 'failed', 'stopped')),
  created_at timestamptz not null default now()
);

create table if not exists tenant_budgets (
  tenant_id uuid primary key references tenants(id),
  monthly_aud numeric(12, 2) not null,
  tier text not null
);

create table if not exists cost_ledger (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  category text not null,
  units numeric(12, 4) not null,
  aud numeric(12, 4) not null,
  at timestamptz not null default now()
);

create table if not exists sharing_preferences (
  tenant_id uuid not null references tenants(id),
  category text not null,
  enabled boolean not null default false,
  primary key (tenant_id, category)
);

create table if not exists shared_items (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  finding_id uuid not null references findings(id),
  category text not null,
  sanitised jsonb not null,
  approved_by uuid,
  approved_at timestamptz,
  stix_id text,
  created_at timestamptz not null default now()
);

create table if not exists integration_tokens (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  provider text not null,
  ciphertext text not null,
  scopes text[] not null,
  created_at timestamptz not null default now(),
  unique (tenant_id, provider)
);

create table if not exists integration_cache (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  provider text not null,
  kind text not null,
  body jsonb not null,
  fetched_at timestamptz not null default now()
);

create table if not exists analyst_assignments (
  tenant_id uuid not null references tenants(id),
  user_id uuid not null references users(id),
  primary key (tenant_id, user_id)
);

do $$
declare
  t text;
begin
  foreach t in array array[
    'agent_runs', 'tenant_budgets', 'cost_ledger', 'sharing_preferences', 'shared_items',
    'integration_tokens', 'integration_cache', 'analyst_assignments'
  ]
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
