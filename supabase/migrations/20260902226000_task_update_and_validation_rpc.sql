drop policy if exists crm_tasks_update on public.crm_tasks;
revoke update on public.crm_tasks from authenticated;

create or replace function public.crm_update_task(
  target_task_id uuid, target_expected_version integer, new_title text, new_description text,
  new_status public.crm_task_status, new_priority public.crm_priority, new_due_at timestamptz,
  new_reminder_at timestamptz, new_assigned_to uuid
)
returns public.crm_tasks language plpgsql security definer set search_path = public as $$
declare current_task public.crm_tasks; updated_task public.crm_tasks; actor_role public.crm_member_role;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if nullif(trim(new_title), '') is null then raise exception 'Title is required'; end if;
  select * into current_task from public.crm_tasks where id = target_task_id for update;
  if not found then raise exception 'Task not found'; end if;
  if not public.crm_is_firm_member(current_task.firm_id) then raise exception 'Forbidden'; end if;
  if current_task.version <> target_expected_version then
    raise exception 'Task changed by another user; reload before saving' using errcode = '40001';
  end if;
  update public.crm_tasks set title = trim(new_title), description = coalesce(new_description, ''),
    status = new_status, priority = new_priority, due_at = new_due_at,
    due_on = new_due_at at time zone 'Europe/Madrid', reminder_at = new_reminder_at,
    assigned_to = new_assigned_to,
    completed_at = case when new_status = 'completed' then coalesce(completed_at, now()) else null end
  where id = target_task_id returning * into updated_task;
  return updated_task;
end;
$$;

create or replace function public.crm_validate_deadline(
  target_task_id uuid, target_expected_version integer, decision text,
  confirmed_due_at timestamptz, source_reference text, professional_note text
)
returns public.crm_tasks language plpgsql security definer set search_path = public as $$
declare current_task public.crm_tasks; updated_task public.crm_tasks; actor_role public.crm_member_role;
begin
  if decision not in ('validated', 'rejected') then raise exception 'Invalid validation decision'; end if;
  select * into current_task from public.crm_tasks where id = target_task_id for update;
  if not found or current_task.kind <> 'deadline' then raise exception 'Deadline not found'; end if;
  if not public.crm_is_firm_member(current_task.firm_id) then raise exception 'Forbidden'; end if;
  select role into actor_role from public.crm_firm_members
  where firm_id = current_task.firm_id and user_id = auth.uid() and status = 'active';
  if actor_role not in ('owner', 'admin', 'lawyer') then
    raise exception 'Only an owner, administrator or lawyer can validate or reject a legal deadline';
  end if;
  if current_task.version <> target_expected_version then
    raise exception 'Deadline changed by another user; reload before validating' using errcode = '40001';
  end if;
  if decision = 'validated' and (confirmed_due_at is null or nullif(trim(source_reference), '') is null) then
    raise exception 'Validated deadlines require a due date and source';
  end if;
  update public.crm_tasks set validation_status = decision,
    due_at = coalesce(confirmed_due_at, due_at), due_on = coalesce(confirmed_due_at, due_at) at time zone 'Europe/Madrid',
    deadline_source = trim(coalesce(source_reference, '')), validation_note = trim(coalesce(professional_note, '')),
    validated_by = case when decision = 'validated' then auth.uid() else null end,
    validated_at = case when decision = 'validated' then now() else null end
  where id = target_task_id returning * into updated_task;
  insert into public.crm_task_events(firm_id, task_id, event_type, payload)
  values (updated_task.firm_id, updated_task.id, 'deadline_' || decision,
    jsonb_build_object('version', updated_task.version, 'has_source', nullif(updated_task.deadline_source, '') is not null));
  return updated_task;
end;
$$;

revoke all on function public.crm_update_task(uuid, integer, text, text, public.crm_task_status, public.crm_priority, timestamptz, timestamptz, uuid) from public, anon;
grant execute on function public.crm_update_task(uuid, integer, text, text, public.crm_task_status, public.crm_priority, timestamptz, timestamptz, uuid) to authenticated;
revoke all on function public.crm_validate_deadline(uuid, integer, text, timestamptz, text, text) from public, anon;
grant execute on function public.crm_validate_deadline(uuid, integer, text, timestamptz, text, text) to authenticated;
