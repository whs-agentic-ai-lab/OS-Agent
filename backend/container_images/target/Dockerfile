FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY container_images/target_service.py /app/target_service.py
COPY container_images/healthcheck.py /app/healthcheck

RUN printf '%s\n' 'target-service-v1' > /app/RUNTIME_CONTRACT \
    && chmod 0555 /app/healthcheck /app/target_service.py

EXPOSE 8080
CMD ["python3", "/app/target_service.py"]
