#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TEST_SUFFIX="$(date +%s)"
TEST_USER="probe_${TEST_SUFFIX}"
TEST_PASS="ProbePass123"
TEST_CHAR="Probe${TEST_SUFFIX: -6}"

echo "[1/5] Build and start local stack"
if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
  docker compose up -d
else
  docker compose up -d --build
fi

echo "[2/5] Wait for healthy containers"
for svc in rathena-db rathena-server; do
  for _ in $(seq 1 60); do
    status="$(docker inspect -f '{{.State.Health.Status}}' "$svc" 2>/dev/null || true)"
    if [[ "$status" == "healthy" ]]; then
      echo "  $svc: healthy"
      break
    fi
    sleep 2
  done
  if [[ "$status" != "healthy" ]]; then
    echo "  $svc: not healthy" >&2
    exit 1
  fi
done

echo "[3/5] Check schema and service exposure"
docker exec rathena-db mariadb -uragnarok -pragnarok -N -e \
  "USE ragnarok; SHOW COLUMNS FROM login LIKE 'user_pass'; SELECT account_id, userid, LENGTH(user_pass), user_pass FROM login LIMIT 5;"

echo "[4/5] Prepare probe account and run protocol tests"
TEST_HASH="$(python3 - <<'PY'
import hashlib
import os

password = "ProbePass123"
salt = os.urandom(16).hex()
digest = hashlib.sha256(bytes.fromhex(salt) + password.encode("utf-8")).hexdigest()
print(f"sha256${salt}${digest}")
PY
)"
TEST_ACCOUNT_ID="$(docker exec rathena-db mariadb -uragnarok -pragnarok -N -e \
  "USE ragnarok; SELECT GREATEST(COALESCE(MAX(account_id),1999999)+1,2000000) FROM login;")"
docker exec rathena-db mariadb -uragnarok -pragnarok -e \
  "USE ragnarok; \
   DELETE FROM \`char\` WHERE \`name\`='${TEST_CHAR}'; \
   DELETE FROM \`login\` WHERE \`userid\`='${TEST_USER}'; \
   INSERT INTO \`login\` (\`account_id\`, \`userid\`, \`user_pass\`, \`sex\`, \`email\`) VALUES (${TEST_ACCOUNT_ID}, '${TEST_USER}', '${TEST_HASH}', 'M', '${TEST_USER}@local.test');"
python3 tools/rathena_login_probe.py --host 127.0.0.1 --port 6900 --username "${TEST_USER}" --password "${TEST_PASS}"
python3 tools/rathena_char_probe.py --host 127.0.0.1 --login-port 6900 --char-port 6121 --username "${TEST_USER}" --password "${TEST_PASS}" --char-name "${TEST_CHAR}"
docker exec rathena-db mariadb -uragnarok -pragnarok -N -e \
  "USE ragnarok; SELECT account_id, userid, user_pass FROM login WHERE userid='${TEST_USER}'; SELECT account_id, char_num, name FROM \`char\` WHERE account_id=${TEST_ACCOUNT_ID};"

echo "[5/5] Scan recent logs for critical messages"
docker logs --tail 200 rathena-server 2>&1 | grep -Ei 'fatal|error|sql' || true

echo "verification_complete=yes"
