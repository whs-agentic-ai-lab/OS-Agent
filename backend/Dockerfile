FROM gcc:14-bookworm AS fixture-builder

COPY runtime_agent/fixtures/identity_reporter.c /src/identity_reporter.c
RUN gcc -O2 -Wall -Wextra -Werror -s \
    -o /identity-reporter /src/identity_reporter.c \
    && chmod 0755 /identity-reporter

FROM python:3.10-slim

ARG OS_AGENT_BUILD_GIT_SHA=unknown
ARG OS_AGENT_BUILD_SOURCE_DIRTY=false
LABEL org.opencontainers.image.revision=$OS_AGENT_BUILD_GIT_SHA
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OS_AGENT_BUILD_GIT_SHA=$OS_AGENT_BUILD_GIT_SHA \
    OS_AGENT_BUILD_SOURCE_DIRTY=$OS_AGENT_BUILD_SOURCE_DIRTY

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY host_runtime ./host_runtime
COPY runtime_agent ./runtime_agent
COPY --from=terraform config/vector/normalize.vrl.tpl ./bootstrap_assets/normalize.vrl.tpl
COPY --from=fixture-builder /identity-reporter ./runtime_agent/fixtures/identity-reporter

RUN printf '%s\n' 'action-path-runtime-v1' > /app/RUNTIME_CONTRACT

RUN groupadd --gid 10003 agent-runtime \
    && useradd --uid 10003 --gid 10003 --create-home agent-runtime
USER agent-runtime

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
