FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends docker.io docker-cli \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir psutil requests

# Debian variants may expose docker client under a different binary name.
# Normalize best-effort; do not fail build here (runtime checks handle hard failure).
RUN if [ -x /usr/bin/docker ]; then \
      ln -sf /usr/bin/docker /usr/local/bin/docker; \
    elif [ -x /usr/bin/docker.io ]; then \
      ln -sf /usr/bin/docker.io /usr/local/bin/docker; \
    fi

RUN if command -v docker >/dev/null 2>&1; then \
      docker --version || true; \
    elif command -v docker.io >/dev/null 2>&1; then \
      docker.io --version || true; \
    else \
      echo "WARN: docker CLI not detected during build"; \
    fi

COPY agent/agent.py /app/agent.py

ENTRYPOINT ["python", "/app/agent.py"]
