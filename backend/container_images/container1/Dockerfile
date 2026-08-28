FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY runtime_agent/runtime.py /app/runtime_agent.py
COPY container_images/target_service.py /app/target_service.py
COPY container_images/healthcheck.py /app/healthcheck

RUN printf '%s\n' 'container1-executor-target-v1' > /app/RUNTIME_CONTRACT \
    && chmod 0555 /app/healthcheck /app/target_service.py /app/runtime_agent.py

EXPOSE 8080
CMD ["python3", "/app/target_service.py"]
