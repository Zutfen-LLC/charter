# Role matrix

Roles are disjoint capability sets assigned per tenant (admin, records, export, operator) or per project (member). A person may hold several roles but a *single action* that requires separation of duties must be completed by different people.

Legend: **Y** allowed, **M** metadata only (ids, hashes, timestamps, states; no content), **-** denied.

| Capability | project_member | tenant_admin | records_officer | export_reviewer | operator |
| --- | --- | --- | --- | --- | --- |
| Use models permitted by project policy | Y | - | - | - | - |
| Read own workspace chats in projects they belong to | Y | - | - | - | - |
| Manage project membership, model policy, budgets | - | Y | - | - | - |
| Create/deactivate users, assign roles (not records/export roles for self) | - | Y | - | - | - |
| View evidence metadata | - | - | Y | M | M |
| View evidence content | - | - | Y (held matters in scope) | Y (only objects in an approved export) | - |
| Place / release a hold | - | - | Y | - | - |
| Approve disposal purge | - | - | Y (not for items they requested) | - | - |
| Request an export | - | - | Y | - | - |
| Approve an export | - | - | - | Y (not their own request) | - |
| Run offline verification | - | - | Y | Y | Y |
| Run recovery / backup / restore | - | - | - | - | Y |
| Read provider credentials | - | - | - | - | - (held by control plane secret store) |
| Edit or delete evidence | - | - | - | - | - |
| Rewrite or delete the audit trail of role/hold changes | - | - | - | - | - |

Rules:

1. **Workspace deletion is not evidence deletion.** Normal users lose access when a chat/project is deleted or they are revoked; they never gain access to evidence.
2. **Role changes and hold/export/purge actions are themselves audited** with actor, time and hold epoch, in an append-only audit log.
3. **Separation of duties:** export requester ≠ export approver; purge requester ≠ purge approver; `tenant_admin` cannot grant themselves `records_officer` or `export_reviewer` without a second `tenant_admin`.
4. **Operators** can keep the system running and restore it but cannot read content, change holds or approve anything.
5. Authorization is evaluated by the control plane on every request, using `tenant_id` and `project_id` from the authenticated session, never from client-supplied fields.
6. Break-glass access, if any, is out of scope for the pilot and must be added as a separately reviewed change.
