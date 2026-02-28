FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends docker.io \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir psutil requests

COPY agent/agent.py /app/agent.py

ENTRYPOINT ["python", "/app/agent.py"]
