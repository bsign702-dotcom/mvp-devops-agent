FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends docker.io \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir psutil requests

# Debian variants may expose docker client as `docker.io` without `docker` symlink.
# Normalize to `docker` because agent code calls `docker`.
RUN if ! command -v docker >/dev/null 2>&1 && command -v docker.io >/dev/null 2>&1; then \
      ln -s "$(command -v docker.io)" /usr/local/bin/docker; \
    fi \
 && command -v docker \
 && docker --version

COPY agent/agent.py /app/agent.py

ENTRYPOINT ["python", "/app/agent.py"]
