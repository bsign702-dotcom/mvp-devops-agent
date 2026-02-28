#!/usr/bin/env bash
set -euo pipefail

AGENT_IMAGE="${AGENT_IMAGE:-bsign/devops-agent:latest}"
CONTAINER_NAME="devops-agent"
INTERVAL_SEC="${INTERVAL_SEC:-15}"
SYSTEMD_UNITS="${SYSTEMD_UNITS:-nginx,ssh}"
TOKEN=""
API=""

usage() {
  cat <<USAGE
Usage: install.sh --token "<token>" --api "http://api.host:8000"

Installs/runs the DevOps agent container with Docker.
Optional env vars before running:
  AGENT_IMAGE (default: $AGENT_IMAGE)
  INTERVAL_SEC (default: $INTERVAL_SEC)
  SYSTEMD_UNITS (default: $SYSTEMD_UNITS)
USAGE
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "This script must run as root. Re-run with sudo." >&2
    exit 1
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --token)
        TOKEN="${2:-}"
        shift 2
        ;;
      --api)
        API="${2:-}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown argument: $1" >&2
        usage
        exit 1
        ;;
    esac
  done

  if [[ -z "$TOKEN" || -z "$API" ]]; then
    echo "Both --token and --api are required." >&2
    usage
    exit 1
  fi

  API="${API%/}"
}

warn_if_localhost_api() {
  case "$API" in
    http://localhost*|https://localhost*|http://127.0.0.1*|https://127.0.0.1*)
      echo "WARNING: API URL uses localhost/127.0.0.1. Inside Docker, that points to the agent container itself."
      echo "For local Docker Desktop testing, use: http://host.docker.internal:8000"
      ;;
  esac
}

install_docker_if_needed() {
  if command -v docker >/dev/null 2>&1; then
    return 0
  fi

  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    DISTRO_ID="${ID:-}"
    DISTRO_LIKE="${ID_LIKE:-}"
  else
    DISTRO_ID=""
    DISTRO_LIKE=""
  fi

  if command -v apt-get >/dev/null 2>&1 && ([[ "$DISTRO_ID" == "ubuntu" || "$DISTRO_ID" == "debian" ]] || [[ "$DISTRO_LIKE" == *debian* ]]); then
    echo "Docker not found. Installing docker.io via apt-get..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io
    systemctl enable docker || true
    systemctl start docker || true
  else
    echo "Docker is not installed and automatic install is only supported for Ubuntu/Debian in this script." >&2
    echo "Install Docker manually, then rerun this script:" >&2
    echo "  https://docs.docker.com/engine/install/" >&2
    exit 1
  fi

  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker installation did not complete successfully." >&2
    exit 1
  fi
}

restart_agent_container() {
  if docker ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
    echo "Replacing existing container: $CONTAINER_NAME"
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi

  echo "Pulling agent image: $AGENT_IMAGE"
  if ! docker pull "$AGENT_IMAGE"; then
    if docker image inspect "$AGENT_IMAGE" >/dev/null 2>&1; then
      echo "Image pull failed, but local image exists. Continuing with local image: $AGENT_IMAGE"
    else
      echo "Failed to pull image and no local image found: $AGENT_IMAGE" >&2
      exit 1
    fi
  fi

  echo "Starting agent container..."
  local run_args=(
    -d
    --name "$CONTAINER_NAME"
    --restart=always
    -e AGENT_TOKEN="$TOKEN"
    -e INGEST_URL="$API/v1/ingest"
    -e INTERVAL_SEC="$INTERVAL_SEC"
    -e SYSTEMD_UNITS="$SYSTEMD_UNITS"
    -v /var/run/docker.sock:/var/run/docker.sock
    -v /var/log:/var/log:ro
  )
  if [[ -d /etc/nginx ]]; then
    run_args+=(-v /etc/nginx:/host_etc_nginx:ro)
  fi
  docker run "${run_args[@]}" "$AGENT_IMAGE" >/dev/null
}

health_check() {
  sleep 2
  if ! docker ps --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
    echo "Agent container is not running." >&2
    docker logs "$CONTAINER_NAME" --tail 100 || true
    exit 1
  fi

  echo
  echo "Agent container is running. Last 30 log lines:"
  docker logs "$CONTAINER_NAME" --tail 30 || true
  echo
  echo "Connected if you see HTTP 2xx in logs"
}

print_troubleshooting() {
  echo
  echo "Troubleshooting commands:"
  echo "  docker ps | grep devops-agent"
  echo "  docker logs devops-agent --tail 200"
  echo "  curl -I $API/health"
}

main() {
  require_root
  parse_args "$@"
  warn_if_localhost_api
  install_docker_if_needed
  restart_agent_container
  health_check
  print_troubleshooting
}

main "$@"
