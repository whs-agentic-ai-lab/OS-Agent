FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY host_runtime ./host_runtime
COPY runtime_agent ./runtime_agent

RUN printf '%s\n' 'action-path-runtime-v1' > /app/RUNTIME_CONTRACT

RUN groupadd --gid 10003 agent-runtime \
    && useradd --uid 10003 --gid 10003 --create-home agent-runtime
USER agent-runtime

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
