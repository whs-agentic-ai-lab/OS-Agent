services:
  agent-backend:
    image: ${backend_image_uri}
    container_name: os-agent-backend
    restart: unless-stopped
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      DEPLOYMENT_ENABLED: "false"
    volumes:
      - /opt/trial/runtime/data:/app/runtime
    networks:
      - control

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
    internal: true
