name: os-agent-experiment

services:
  container1:
    image: ${container1_image_uri}
    container_name: os-agent-container1
    init: true
    restart: unless-stopped
    user: "${c1_uid}:${c1_gid}"
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    group_add:
      - "${supervisor_gid}"
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=64m
      - /run:rw,nosuid,nodev,size=16m
    volumes:
      - /srv/os-agent/targets/container1:/workspace:rw
      - /run/os-agent:/run/os-agent:rw
    environment:
      OS_AGENT_EXECUTOR_ID: C1
      OS_AGENT_TARGET_ID: C1
      OS_AGENT_ACTION_PATHS: C1U1,C1C2,C1U2,C1C3
      OS_AGENT_TOPOLOGY_REVISION: ${topology_revision}
    networks: [c1_c2, c1_c3]
    healthcheck:
      test: ["CMD", "/app/healthcheck"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 10s
    pids_limit: 128
    mem_limit: 384m
    cpus: 0.75
    logging:
      driver: json-file
      options:
        max-size: 20m
        max-file: "5"
        labels: os_agent.endpoint_id,os_agent.owner_id,os_agent.role,os_agent.topology_revision
    labels:
      os_agent.managed: "true"
      os_agent.endpoint_id: C1
      os_agent.owner_id: U1
      os_agent.role: executor,target
      os_agent.topology_revision: ${topology_revision}

  container2:
    image: ${target_image_uri}
    container_name: os-agent-container2
    init: true
    restart: unless-stopped
    user: "${c2_uid}:${c2_gid}"
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=64m
    volumes:
      - /srv/os-agent/targets/container2:/workspace:rw
    environment:
      OS_AGENT_TARGET_ID: C2
      OS_AGENT_TOPOLOGY_REVISION: ${topology_revision}
    networks: [c1_c2]
    healthcheck:
      test: ["CMD", "/app/healthcheck"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 10s
    pids_limit: 64
    mem_limit: 256m
    cpus: 0.50
    logging:
      driver: json-file
      options:
        max-size: 20m
        max-file: "5"
        labels: os_agent.endpoint_id,os_agent.owner_id,os_agent.role,os_agent.topology_revision
    labels:
      os_agent.managed: "true"
      os_agent.endpoint_id: C2
      os_agent.owner_id: U1
      os_agent.role: target
      os_agent.topology_revision: ${topology_revision}

  container3:
    image: ${target_image_uri}
    container_name: os-agent-container3
    init: true
    restart: unless-stopped
    user: "${c3_uid}:${c3_gid}"
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=64m
    volumes:
      - /srv/os-agent/targets/container3:/workspace:rw
    environment:
      OS_AGENT_TARGET_ID: C3
      OS_AGENT_TOPOLOGY_REVISION: ${topology_revision}
    networks: [c1_c3]
    healthcheck:
      test: ["CMD", "/app/healthcheck"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 10s
    pids_limit: 64
    mem_limit: 256m
    cpus: 0.50
    logging:
      driver: json-file
      options:
        max-size: 20m
        max-file: "5"
        labels: os_agent.endpoint_id,os_agent.owner_id,os_agent.role,os_agent.topology_revision
    labels:
      os_agent.managed: "true"
      os_agent.endpoint_id: C3
      os_agent.owner_id: U2
      os_agent.role: target
      os_agent.topology_revision: ${topology_revision}

networks:
  c1_c2:
    name: os-agent-c1-c2
    internal: true
    labels:
      os_agent.managed: "true"
      os_agent.allowed_path: C1C2
      os_agent.topology_revision: ${topology_revision}
  c1_c3:
    name: os-agent-c1-c3
    internal: true
    labels:
      os_agent.managed: "true"
      os_agent.allowed_path: C1C3
      os_agent.topology_revision: ${topology_revision}
