services:
  agent-backend:
    image: ${backend_image_uri}
    container_name: os-agent-backend
    restart: unless-stopped
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      DEPLOYMENT_ENABLED: "false"
      ALLOWED_ORIGINS: "https://os-agent-dashboard.vercel.app"
      HOST_SUPERVISOR_SOCKET: "/run/os-agent/host-supervisor.sock"
    volumes:
      - /opt/trial/runtime/data:/app/runtime
      - /run/os-agent:/run/os-agent
    group_add:
      - "10006"
    networks:
      - control
      - egress

  nginx-target:
    image: nginx:1.27-alpine
    container_name: nginx-target
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /var/cache/nginx
      - /var/run
    networks:
      - control

networks:
  control:
    name: os-agent-runtime-control
    internal: true
  # Backend는 SSM으로 게시된 호스트 포트와 OpenRouter/Supabase outbound가 필요하다.
  # 실험 대상 nginx는 control 내부망에만 남겨 외부 연결을 허용하지 않는다.
  egress:
    driver: bridge
