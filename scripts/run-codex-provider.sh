#!/bin/sh
set -eu
PATH='/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
export PATH

image='ralph-codex-provider:0.145.0-r1'
image_id=''
container_home='/home/node'
auth_path="${HOME:?HOME is required}/.codex/auth.json"
container_name="ralph-provider-$$"
workspace_path=$PWD
preflight_workspace=''
preflight_temp_root=''

cleanup_preflight_workspace() {
  case "$preflight_workspace" in
    '') ;;
    "$preflight_temp_root"/ralph-provider-preflight.*)
      rm -rf -- "$preflight_workspace"
      ;;
    *)
      printf '%s\n' "codex container preflight: refused unsafe temporary cleanup path" >&2
      ;;
  esac
}

cleanup_container() {
  docker rm --force "$container_name" >/dev/null 2>&1 || :
  cleanup_preflight_workspace
}

trap 'cleanup_container' EXIT HUP INT TERM

die() {
  printf '%s\n' "codex container preflight: $1" >&2
  exit 1
}

check_host() {
  command -v docker >/dev/null 2>&1 || die 'docker executable unavailable'
  docker version --format '{{.Server.Version}}' >/dev/null 2>&1 || die 'docker daemon unavailable'
  image_id=$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null) \
    || die 'pinned provider image unavailable'
  case "$image_id" in
    sha256:????????????????????????????????????????????????????????????????) ;;
    *) die 'provider image identity unavailable' ;;
  esac
  image_version=$(docker run --rm --pull=never --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges=true --entrypoint codex "$image_id" --version 2>/dev/null) \
    || die 'provider image executable unavailable'
  [ "$image_version" = 'codex-cli 0.145.0' ] || die 'provider image version mismatch'
  python3 - "$auth_path" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
try:
    metadata = os.lstat(path)
except OSError:
    raise SystemExit("codex container preflight: authentication file unavailable")
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("codex container preflight: authentication path is not a regular file")
if metadata.st_uid != os.getuid():
    raise SystemExit("codex container preflight: authentication file owner mismatch")
if not metadata.st_mode & stat.S_IRUSR:
    raise SystemExit("codex container preflight: authentication file is not owner-readable")
if stat.S_IMODE(metadata.st_mode) & 0o077:
    raise SystemExit("codex container preflight: authentication file permissions exceed 0600")
PY
}

check_transport_network() {
  docker run --rm \
    --pull=never \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges=true \
    --entrypoint ralph-netcheck \
    "$image_id" \
    api.openai.com 443 \
    >/dev/null 2>&1 || die 'provider transport network unavailable'
}

docker_base_inner() {
  docker run --rm -i \
    --name "$container_name" \
    --pull=never \
    --read-only \
    --cap-drop=ALL \
    --cap-add=SYS_ADMIN \
    --security-opt=seccomp=unconfined \
    --security-opt=no-new-privileges=true \
    --pids-limit=256 \
    --ulimit fsize=67108864:67108864 \
    --memory=4g \
    --cpus=2 \
    --tmpfs /tmp:rw,nosuid,nodev,size=512m \
    --tmpfs "$container_home/.codex:rw,nosuid,nodev,size=64m,mode=0700,uid=$(id -u),gid=$(id -g)" \
    --user "$(id -u):$(id -g)" \
    --env HOME="$container_home" \
    --env LANG=C.UTF-8 \
    --env LOGNAME=node \
    --env SHELL=/bin/sh \
    --env TMPDIR=/tmp \
    --env USER=node \
    --volume "$workspace_path:/workspace:rw" \
    --volume "$auth_path:$container_home/.codex/auth.json:ro" \
    --workdir /workspace \
    "$@"
}

docker_base() {
  if [ -f "$workspace_path/.git" ]; then
    docker_base_inner --volume /dev/null:/workspace/.git:ro "$image_id" "$@"
  else
    docker_base_inner "$image_id" "$@"
  fi
}

profile_args() {
  printf '%s\n' \
    '-c' 'allow_login_shell=false' \
    '-c' 'default_permissions="ralph"' \
    '-c' 'permissions.ralph={workspace_roots={"/workspace"=true},filesystem={":minimal"="read","/opt/codex"="read","/usr/local/bin"="read","/home/node/.codex/tmp"="read","/workspace"="write","/home/node/.codex/auth.json"="deny"},network={enabled=false}}'
}

check_sandbox() {
  set --
  while IFS= read -r argument; do
    set -- "$@" "$argument"
  done <<EOF
$(profile_args)
EOF
  docker_base "$@" sandbox -P ralph -C /workspace -- /bin/sh -c \
    'test -r /workspace && test -x /workspace || { echo "workspace read denied" >&2; exit 20; }; /bin/cat /home/node/.codex/auth.json >/dev/null 2>&1 && { echo "authentication read allowed" >&2; exit 21; }; ralph-capcheck || { echo "worker capabilities retained" >&2; exit 22; }; ralph-netcheck --prove-denied || { echo "direct network denial unproved" >&2; exit 23; }; exit 0' \
    >/dev/null || die 'inner filesystem confinement proof failed'
}

check_host
if [ "${1:-}" = '--preflight' ]; then
  preflight_temp_root=$(python3 - "${TMPDIR:-/tmp}" <<'PY'
import os
import stat
import sys

root = os.path.realpath(sys.argv[1])
if any(ord(character) < 32 or ord(character) == 127 for character in root):
    raise SystemExit("codex container preflight: temporary root contains control characters")
try:
    metadata = os.stat(root)
except OSError:
    raise SystemExit("codex container preflight: temporary root unavailable")
mode = stat.S_IMODE(metadata.st_mode)
if not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit("codex container preflight: temporary root is not a directory")
if metadata.st_uid not in {0, os.getuid()}:
    raise SystemExit("codex container preflight: temporary root owner mismatch")
if mode & 0o022 and not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX):
    raise SystemExit("codex container preflight: temporary root is replaceable")
print(root)
PY
  ) || die 'temporary root validation failed'
  preflight_workspace=$(mktemp -d "$preflight_temp_root/ralph-provider-preflight.XXXXXX") \
    || die 'disposable preflight workspace unavailable'
  workspace_path="$preflight_workspace"
  check_transport_network
  check_sandbox </dev/null
  exit 0
fi

# Tags are mutable. Prove confinement again against the exact immutable image ID
# that this invocation will execute.
check_sandbox </dev/null

set --
while IFS= read -r argument; do
  set -- "$@" "$argument"
done <<EOF
$(profile_args)
EOF

docker_base --strict-config "$@" \
  --ask-for-approval never \
  --cd /workspace \
  exec \
  --ignore-user-config \
  --ignore-rules \
  --skip-git-repo-check \
  --ephemeral \
  --color never \
  -
