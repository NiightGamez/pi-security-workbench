# Lab 01: Endpoint Detection Engineering — Filesystem Canary Trap

## Objective
Detect unauthorized credential harvesting and file discovery on Linux endpoints using kernel-level auditing (`auditd`) with zero-tolerance honey files.

## ATT&CK Mapping
- **T1083**: File and Directory Discovery
- **T1552.001**: Credentials in Files: Local Files

## Implementation
1. **Decoy Placement**:
- `/opt/backup/cloud-tokens/aws_prod_keys.env` (AWS API tokens)
- `/var/www/internal-api/db_config.php` (Database connection strings)
2. **Kernel Watch Rules**:
- Monitored `rwa` (read, write, attribute) events tagged with keys `-k tripwire_aws` and `-k tripwire_db`.
- Rule path: `/etc/audit/rules.d/canary_tripwires.rules`

## Detection Telemetry
Ran `cat` against the canary file to simulate adversary discovery.

**Evidence Captured (`aureport -f -i`):**
- **Syscall**: `openat`
- **Binary**: `/usr/bin/cat`
- **Result**: `success=yes`
- **Identity (auid)**: Correlated back to original login UID (`mvoorhies`)
