# Host executor/targets와 분리된 container runtime identity 실행
-a always,exit -F arch=b64 -S execve,execveat -F euid=${u1_uid} -k osagent_u1_exec
-a always,exit -F arch=b32 -S execve,execveat -F euid=${u1_uid} -k osagent_u1_exec
-a always,exit -F arch=b64 -S execve,execveat -F euid=${u2_uid} -k osagent_u2_exec
-a always,exit -F arch=b32 -S execve,execveat -F euid=${u2_uid} -k osagent_u2_exec
-a always,exit -F arch=b64 -S execve,execveat -F euid=${c1_uid} -k osagent_c1_exec
-a always,exit -F arch=b32 -S execve,execveat -F euid=${c1_uid} -k osagent_c1_exec
-a always,exit -F arch=b64 -S execve,execveat -F euid=${c2_uid} -k osagent_c2_exec
-a always,exit -F arch=b32 -S execve,execveat -F euid=${c2_uid} -k osagent_c2_exec
-a always,exit -F arch=b64 -S execve,execveat -F euid=${c3_uid} -k osagent_c3_exec
-a always,exit -F arch=b32 -S execve,execveat -F euid=${c3_uid} -k osagent_c3_exec

# identity/capability 변경
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid,setresuid,setresgid,capset -F euid=${u1_uid} -k osagent_u1_identity
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid,setresuid,setresgid,capset -F euid=${u1_uid} -k osagent_u1_identity
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid,setresuid,setresgid,capset -F euid=${u2_uid} -k osagent_u2_identity
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid,setresuid,setresgid,capset -F euid=${u2_uid} -k osagent_u2_identity

# root-owned Supervisor가 수행하는 namespace/mount/Docker 경계 조작
-a always,exit -F arch=b64 -S setns,unshare,mount,umount2 -F euid=0 -k osagent_boundary
-a always,exit -F arch=b32 -S setns,unshare,mount,umount2 -F euid=0 -k osagent_boundary
-a always,exit -F arch=b64 -S execve,execveat -F euid=0 -F exe=/usr/bin/docker -k osagent_docker_exec

# 고정 target state
-w /srv/os-agent/targets/host1 -p wa -k osagent_host1_state
-w /srv/os-agent/targets/host2 -p wa -k osagent_host2_state
-w /srv/os-agent/targets/container1 -p wa -k osagent_container1_state
-w /srv/os-agent/targets/container2 -p wa -k osagent_container2_state
-w /srv/os-agent/targets/container3 -p wa -k osagent_container3_state

# 실행 계약과 privileged control plane
-w /opt/os-agent/bin -p wa -k osagent_runtime_change
-w /etc/os-agent -p wa -k osagent_config_change
-w /etc/systemd/system/os-agent-host-supervisor.service -p wa -k osagent_service_change
-w /var/run/docker.sock -p rwxa -k osagent_docker_socket

# 계정, sudo, persistence, Docker 설정
-w /etc/passwd -p wa -k osagent_accounts
-w /etc/group -p wa -k osagent_accounts
-w /etc/shadow -p wa -k osagent_accounts
-w /etc/sudoers -p wa -k osagent_sudo
-w /etc/sudoers.d -p wa -k osagent_sudo
-w /etc/systemd/system -p wa -k osagent_systemd
-w /etc/cron.d -p wa -k osagent_cron
-w /var/spool/cron/crontabs -p wa -k osagent_cron
-w /etc/docker/daemon.json -p wa -k osagent_docker_config
