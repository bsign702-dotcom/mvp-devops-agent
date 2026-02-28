FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends docker.io \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir psutil requests

# Fail fast at build-time if Docker CLI is not present in the image.
RUN command -v docker && docker --version

COPY agent/agent.py /app/agent.py

ENTRYPOINT ["python", "/app/agent.py"]
