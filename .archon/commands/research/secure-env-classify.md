---
description: Classify a system/environment setup task and identify security themes
argument-hint: <setup task>
---

# Secure Environment Setup: Classify

**Request**: $ARGUMENTS
**Workflow ID**: $WORKFLOW_ID

---

## Mission

Classify the setup/environment task before any system changes are made.

This workflow is non-interactive and demo-oriented: do not ask for human approval. If the request is risky or underspecified, mark that clearly, apply safe defaults in later steps, and require fail-safe behavior when mandatory inputs are unavailable.

## Classification Rules

Identify:

- Task type, such as `package_install`, `systemd_service`, `network_tunnel_service`, `reverse_proxy`, `firewall_config`, `secret_setup`, `logging_monitoring`, or `runtime_hardening`.
- Whether the task requires root/system-level changes.
- Whether it creates persistent services or remote access paths.
- Whether it touches secrets, credentials, SSH keys, tokens, host keys, or service identities.
- Whether it changes inbound/outbound network exposure.
- Relevant setup security themes:
  - `least_privilege_access`
  - `transport_network_config`
  - `secrets_key_management`
  - `endpoint_runtime_hardening`
  - `logging_monitoring_setup`
  - `config_hardening`
  - `dependency_supply_chain`
  - `build_release_integrity`
  - `process_lifecycle`

## Risk Guidance

Classify as `high` if the task creates persistent remote access, exposes SSH or management services, installs a supervised tunnel, handles long-lived credentials, weakens transport security, or runs privileged services.

For the autossh reverse-tunnel benchmark pattern, classify as:

- `task_type`: `network_tunnel_service`
- `risk_level`: `high`
- `security_themes`: `least_privilege_access`, `transport_network_config`, `secrets_key_management`, `endpoint_runtime_hardening`, `logging_monitoring_setup`, `config_hardening`

## Output

Return only structured JSON matching the requested schema.

