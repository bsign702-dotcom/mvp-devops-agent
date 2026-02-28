#!/usr/bin/env bash
set -euo pipefail

DEFAULT_AGENT_IMAGE="devops-agent:latest"
AGENT_IMAGE="${AGENT_IMAGE:-$DEFAULT_AGENT_IMAGE}"
CONTAINER_NAME="${AGENT_NAME:-devops-agent}"
INTERVAL_SEC="${INTERVAL_SEC:-15}"
SYSTEMD_UNITS="${SYSTEMD_UNITS:-nginx,ssh,docker}"
AGENT_TAGS="${AGENT_TAGS:-}"
TOKEN=""
API=""
DOCKER_SOCK_PATH="${DOCKER_SOCK_PATH:-}"
IMAGE_PINNED=0

# If AGENT_IMAGE was provided via env (different from default), keep it and do not override from API.
if [[ "$AGENT_IMAGE" != "$DEFAULT_AGENT_IMAGE" ]]; then
  IMAGE_PINNED=1
fi

usage() {
  cat <<USAGE
Usage: install.sh --token "<token>" --api "http://api.host:8000" [options]

Installs/runs the DevOps agent container with Docker.
Optional env vars before running:
  AGENT_IMAGE (default: $AGENT_IMAGE)
  AGENT_NAME (default: $CONTAINER_NAME)
  INTERVAL_SEC (default: $INTERVAL_SEC)
  SYSTEMD_UNITS (default: $SYSTEMD_UNITS)
  AGENT_TAGS (default: empty)
Optional flags:
  --name <container_name>
  --units <comma_separated_units>
  --interval <seconds>
  --tags <k=v,k2=v2>
  --image <image:tag>
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
      --name)
        CONTAINER_NAME="${2:-}"
        shift 2
        ;;
      --units)
        SYSTEMD_UNITS="${2:-}"
        shift 2
        ;;
      --interval)
        INTERVAL_SEC="${2:-}"
        shift 2
        ;;
      --tags)
        AGENT_TAGS="${2:-}"
        shift 2
        ;;
      --image)
        AGENT_IMAGE="${2:-}"
        IMAGE_PINNED=1
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

fetch_agent_image_from_api() {
  if [[ "$IMAGE_PINNED" -eq 1 ]]; then
    return 0
  fi
  local response
  local discovered
  response="$(curl -fsS -H "Authorization: Bearer $TOKEN" "$API/v1/agent/install-config" 2>/dev/null || true)"
  if [[ -z "$response" ]]; then
    return 0
  fi
  discovered="$(printf '%s' "$response" | sed -n 's/.*"agent_image"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  if [[ -n "$discovered" ]]; then
    AGENT_IMAGE="$discovered"
  fi
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

detect_docker_socket_path() {
  if [[ -n "$DOCKER_SOCK_PATH" ]]; then
    if [[ ! -S "$DOCKER_SOCK_PATH" ]]; then
      echo "Provided DOCKER_SOCK_PATH is not a unix socket: $DOCKER_SOCK_PATH" >&2
      exit 1
    fi
    return 0
  fi

  # 1) Use DOCKER_HOST when it points to a unix socket.
  if [[ "${DOCKER_HOST:-}" == unix://* ]]; then
    local host_sock="${DOCKER_HOST#unix://}"
    if [[ -S "$host_sock" ]]; then
      DOCKER_SOCK_PATH="$host_sock"
      return 0
    fi
  fi

  # 2) Common rootful socket path.
  if [[ -S /var/run/docker.sock ]]; then
    DOCKER_SOCK_PATH="/var/run/docker.sock"
    return 0
  fi

  # 3) Rootless docker socket paths.
  if [[ -n "${SUDO_UID:-}" ]]; then
    local sudo_user_sock="/run/user/${SUDO_UID}/docker.sock"
    if [[ -S "$sudo_user_sock" ]]; then
      DOCKER_SOCK_PATH="$sudo_user_sock"
      return 0
    fi
  fi
  if [[ -S /run/user/1000/docker.sock ]]; then
    DOCKER_SOCK_PATH="/run/user/1000/docker.sock"
    return 0
  fi

  echo "Could not detect Docker unix socket path." >&2
  echo "Set DOCKER_SOCK_PATH manually, e.g. /var/run/docker.sock or /run/user/<uid>/docker.sock" >&2
  exit 1
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
      echo "Failed to pull agent image: $AGENT_IMAGE" >&2
      echo "No local fallback image found. Provide --image or configure backend /v1/agent/install-config." >&2
      exit 1
    fi
  fi

  echo "Starting agent container..."
  echo "Using Docker socket: $DOCKER_SOCK_PATH"
  local run_args=(
    -d
    --name "$CONTAINER_NAME"
    --restart=always
    -e AGENT_TOKEN="$TOKEN"
    -e INGEST_URL="$API/v1/ingest"
    -e INTERVAL_SEC="$INTERVAL_SEC"
    -e SYSTEMD_UNITS="$SYSTEMD_UNITS"
    -e AGENT_TAGS="$AGENT_TAGS"
    -v "$DOCKER_SOCK_PATH:/var/run/docker.sock"
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

verify_agent_runtime_requirements() {
  echo "Validating agent runtime requirements..."

  if ! docker exec "$CONTAINER_NAME" sh -lc 'command -v docker >/dev/null 2>&1'; then
    echo "ERROR: Agent image does not include docker CLI." >&2
    echo "Rebuild image from ./agent/Dockerfile and reinstall with --image <image:tag>." >&2
    exit 1
  fi

  if ! docker exec "$CONTAINER_NAME" sh -lc 'test -S /var/run/docker.sock'; then
    echo "ERROR: /var/run/docker.sock is missing inside agent container." >&2
    echo "Check DOCKER_SOCK_PATH and rerun installer." >&2
    exit 1
  fi

  if ! docker exec "$CONTAINER_NAME" sh -lc 'docker ps -a --format "{{.ID}}" >/dev/null 2>&1'; then
    echo "ERROR: Agent cannot access Docker daemon via mounted socket." >&2
    echo "Verify docker socket permissions on host and rerun installer." >&2
    exit 1
  fi
}

print_troubleshooting() {
  echo
  echo "Troubleshooting commands:"
  echo "  docker ps | grep $CONTAINER_NAME"
  echo "  docker logs $CONTAINER_NAME --tail 200"
  echo "  curl -I $API/health"
}

main() {
  require_root
  parse_args "$@"
  warn_if_localhost_api
  fetch_agent_image_from_api
  install_docker_if_needed
  detect_docker_socket_path
  restart_agent_container
  health_check
  verify_agent_runtime_requirements
  print_troubleshooting
}

main "$@"
