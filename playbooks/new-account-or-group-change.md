# Playbook: Account Creation or Group Membership Change

**Relevant events:** `4720`, `4722`, `4728`, `4732`, `4738`.

## Triage
1. Identify the actor (subject) and target account/member from the event XML.
2. Determine the group name and whether it grants administrative or sensitive access.
3. Check the change-management ticket and identity lifecycle records.
4. Review nearby `4624` and `4672` events for the actor's session.
5. Establish whether the action affected one endpoint, a server, or a domain controller.

## Escalate when
- The actor is unexpected or recently compromised.
- The target is a privileged group or dormant account.
- There is no approved change and the action occurs outside the normal window.

Preserve the original event and relevant authentication evidence before making changes. Use the organization's access revocation process if unauthorized activity is confirmed.
