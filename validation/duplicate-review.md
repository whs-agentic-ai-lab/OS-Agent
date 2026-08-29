# Semantic duplicate review

Exact Tool ID + Action duplicates: **0**

| Candidate | Decision | Mechanism distinction | Reason |
| --- | --- | --- | --- |
| `process.procfs:read_mem` ↔ `process.memory:read` | KEEP_SEPARATE | /proc/<pid>/mem file interface; process_vm_readv syscall | The target memory overlaps, but kernel interface and independent verifier observations differ. |
| `process.pidfd:getfd` ↔ `fd.transfer:pidfd_getfd` | KEEP_SEPARATE | process lifecycle/pidfd control; FD transfer/object identity | Both reach pidfd_getfd, while one verifies process/pidfd lifecycle and the other verifies transferred FD identity and repeatability. |
| `fd.transfer:scm_send/scm_receive` ↔ `unix_socket.fd_transfer:send_fd/receive_fd` | KEEP_SEPARATE | generic FD transfer catalogue; Unix socket ancillary-data control plane | SCM_RIGHTS overlaps, but the Unix-socket family additionally owns socket/credential semantics and a different verifier scope. |
| `file.open` ↔ `file.content` ↔ `fd.operate` | KEEP_SEPARATE | open/openat semantics; path content operations; already-open descriptor operations | They operate at different lifecycle layers and verify different kernel objects. |
| `filecap.manage` ↔ `persist.filecap` | KEEP_SEPARATE | capability execution probe; persistent filesystem capability installation | The xattr mechanism overlaps, but target lifecycle and persistence verifier intent differ. |
| `systemd.unit_*` ↔ `persist.systemd_*` | KEEP_SEPARATE | systemd runtime/unit control plane; persistence installation and activation | Runtime management and persistence establishment have distinct targets, reset scopes, and verification goals. |
| `kernel.sysctl` ↔ `persist.sysctl` | KEEP_SEPARATE | live kernel sysctl interface; persistent sysctl configuration plus reload | One validates the live kernel control and the other validates boot-persistent configuration. |
| `general file tools` ↔ `audit/journal mutation tools` | KEEP_SEPARATE | generic registered path; audit/journal control and evidence plane | Logging tools require subsystem-specific policy, evidence correlation, and terminal reset handling. |
| `docker.*` ↔ `containerd.*` ↔ `oci.*` | KEEP_SEPARATE | Docker Engine API/CLI; containerd task API; OCI runtime invocation | They target different control planes even when the resulting container effect is similar. |
