-- Lookups the API needs before it knows which tenant a request belongs to.
-- Row-level security hides other tenants from cti_app, so these run as the
-- table owner and return only the narrow columns the caller needs.

alter table invites add column if not exists accepted_at timestamptz;

-- A warning can be shared without being tied to one finding.
alter table shared_items alter column finding_id drop not null;

create or replace function cti_user_tenants(p_user uuid)
returns table (tenant_id uuid, name text, role text)
language sql stable security definer set search_path = public as $$
  select t.id, t.name, m.role
  from memberships m join tenants t on t.id = m.tenant_id
  where m.user_id = p_user
  order by m.created_at;
$$;

create or replace function cti_accept_invites(p_user uuid, p_email text)
returns integer
language plpgsql security definer set search_path = public as $$
declare
  accepted integer := 0;
  item record;
begin
  for item in
    select id, tenant_id, role from invites
    where lower(email) = lower(p_email) and accepted_at is null
    for update
  loop
    insert into memberships (id, tenant_id, user_id, role)
    values (gen_random_uuid(), item.tenant_id, p_user, item.role)
    on conflict (tenant_id, user_id) do nothing;
    update invites set accepted_at = now() where id = item.id;
    accepted := accepted + 1;
  end loop;
  return accepted;
end;
$$;

create or replace function cti_domain_by_email_token(p_hash text)
returns table (id uuid, tenant_id uuid)
language sql stable security definer set search_path = public as $$
  select id, tenant_id from verified_domains
  where email_token_hash = p_hash and status = 'email_pending';
$$;

revoke all on function cti_user_tenants(uuid) from public;
revoke all on function cti_accept_invites(uuid, text) from public;
revoke all on function cti_domain_by_email_token(text) from public;
grant execute on function cti_user_tenants(uuid) to cti_app;
grant execute on function cti_accept_invites(uuid, text) to cti_app;
grant execute on function cti_domain_by_email_token(text) to cti_app;

create index if not exists observations_domain_idx on observations (extracted_domain) where extracted_domain is not null;
-- The worker raises one finding per tenant and subject, for example one per lookalike domain.
alter table findings add column if not exists dedupe_key text;
create unique index if not exists findings_dedupe_idx on findings (tenant_id, dedupe_key) where dedupe_key is not null;
