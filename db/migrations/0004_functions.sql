-- Cross-tenant helpers that the application role is allowed to call.
-- They are security definer so row level security still holds for ordinary queries.

create or replace function accept_invites(p_user_id uuid, p_email text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  tid uuid;
begin
  select tenant_id into tid
    from invites
    where lower(email) = lower(p_email)
    limit 1;
  insert into memberships (tenant_id, user_id, role)
  select i.tenant_id, p_user_id, i.role
    from invites i
    where lower(i.email) = lower(p_email)
  on conflict (tenant_id, user_id) do nothing;
  delete from invites where lower(email) = lower(p_email);
  return tid;
end $$;

create or replace function verify_domain_email(p_token text)
returns table(id uuid, tenant_id uuid)
language plpgsql
security definer
set search_path = public
as $$
begin
  return query
  update verified_domains
    set status = 'verified',
        method = 'email',
        verified_at = now(),
        txt_missing_since = null
    where token = p_token and status = 'pending'
    returning verified_domains.id, verified_domains.tenant_id;
end $$;

revoke all on function accept_invites(uuid, text) from public;
revoke all on function verify_domain_email(text) from public;
grant execute on function accept_invites(uuid, text) to cti_app;
grant execute on function verify_domain_email(text) to cti_app;
