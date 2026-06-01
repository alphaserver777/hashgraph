#!/usr/bin/env bash
# Provoke REAL security events on target servers.
#
# Each action triggers a real OS-level event (real sshd failure, real
# file modification, real new PID, real iptables rule). Our collectors
# read it from the system logs and journals as if it happened naturally.
# The load generator does NOT call /event/emit directly — that would
# be synthetic and would invalidate the model evaluation.
#
# All actions roll their changes back after measurement, so the target
# system returns to its original state.
#
# Usage:
#   scripts/experiment/provoke_events.sh \
#     --targets France,Germany,Germany2 \
#     --kind all \
#     --count 1 \
#     --experiment-id baseline-001
#
# Kinds:
#   failed_logins   — 15 неудачных ssh-входов (Failed password in auth.log)
#   remote_login    — успешный ssh-вход root (Accepted in auth.log)
#   file_modified   — изменение /etc/motd (mtime+sha256 change)
#   iptables_rule   — добавление+удаление правила iptables в отдельной цепочке
#   malware_process — запуск процесса с именем из blocklist (xmrig)
#   privileged_proc — запуск нового PID c EUID=0
#   all             — все шесть категорий
set -euo pipefail

TARGETS=""
KIND="all"
COUNT=1
EXPERIMENT_ID="manual-$(date +%s)"
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --targets) TARGETS=$2; shift 2;;
    --kind) KIND=$2; shift 2;;
    --count) COUNT=$2; shift 2;;
    --experiment-id) EXPERIMENT_ID=$2; shift 2;;
    --dry-run) DRY_RUN=true; shift;;
    *) echo "unknown: $1"; exit 2;;
  esac
done

if [[ -z "$TARGETS" ]]; then
  echo "Usage: $0 --targets host1,host2 [--kind all|failed_logins|...] [--count N] [--experiment-id TAG]"
  exit 2
fi

IFS=',' read -ra TARGET_LIST <<< "$TARGETS"

log() {
  echo "[$(date +%H:%M:%S)] $*"
}

run_or_show() {
  if [[ "$DRY_RUN" == true ]]; then
    echo "    DRY: $*"
  else
    eval "$*"
  fi
}

#------------------------------------------------------------------
# 1) Failed logins: 15 неудачных попыток ssh с неверным пользователем
#    sshd запишет 'Failed password' в auth.log → коллектор linux_journald
#    видит → admin_login_failure ×N + failed_login_burst
#------------------------------------------------------------------
provoke_failed_logins() {
  local target=$1
  log "  [$target] провокация неудачных входов (15 попыток)"
  local target_ip
  target_ip=$(ssh -o ConnectTimeout=5 "$target" 'ip -4 addr show scope global | grep -oE "inet [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" | head -1 | awk "{print \$2}"')
  for i in $(seq 1 15); do
    run_or_show "ssh -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no nobody_exp_${EXPERIMENT_ID}@$target_ip true 2>/dev/null || true"
  done
  log "  [$target] неудачные входы провоцированы"
}

#------------------------------------------------------------------
# 2) Remote login: успешный ssh-вход с тестовой команды
#    sshd запишет 'Accepted publickey' в auth.log → коллектор linux_auth
#    видит → admin_ssh_login_success
#------------------------------------------------------------------
provoke_remote_login() {
  local target=$1
  log "  [$target] провокация успешного удалённого входа"
  run_or_show "ssh -o ConnectTimeout=5 '$target' 'logger -t mdrj-experiment \"experiment=$EXPERIMENT_ID remote_login_test\"; true'"
}

#------------------------------------------------------------------
# 3) Critical file modified: меняем /etc/motd (НЕ критический по смыслу,
#    но в watch_paths можно добавить — для эксперимента трогаем motd
#    либо отдельный файл-приманку под список наблюдения).
#    Откат — восстановление содержимого.
#------------------------------------------------------------------
provoke_file_modified() {
  local target=$1
  log "  [$target] провокация изменения наблюдаемого файла"
  run_or_show "ssh '$target' bash -s <<'REMOTE'
mkdir -p /var/lib/mdrj
touch /var/lib/mdrj/watch_canary
ORIG=\$(cat /var/lib/mdrj/watch_canary 2>/dev/null || true)
echo \"# experiment=$EXPERIMENT_ID at \$(date -Is)\" > /var/lib/mdrj/watch_canary
sleep 2
echo -n \"\$ORIG\" > /var/lib/mdrj/watch_canary
REMOTE"
  log "  [$target] изменение файла-приманки выполнено"
}

#------------------------------------------------------------------
# 4) iptables: добавляем правило в отдельную цепочку, через секунду
#    удаляем. iptables-save diff поймает наш коллектор linux_firewall
#    → iptables_rule_changed
#------------------------------------------------------------------
provoke_iptables_rule() {
  local target=$1
  log "  [$target] провокация изменения iptables"
  run_or_show "ssh '$target' bash -s <<'REMOTE'
CHAIN=MDRJ_EXP_$EXPERIMENT_ID
iptables -N \$CHAIN 2>/dev/null || iptables -F \$CHAIN
iptables -A \$CHAIN -s 192.0.2.99 -j DROP
sleep 2
iptables -F \$CHAIN
iptables -X \$CHAIN
REMOTE"
  log "  [$target] правило iptables изменено и откатано"
}

#------------------------------------------------------------------
# 5) Malware process: создаём бинарь под именем из blocklist (xmrig)
#    из /bin/sleep, запускаем, удаляем. linux_proc видит новый pid
#    с basename из blocklist → known_malicious_process
#------------------------------------------------------------------
provoke_malware_process() {
  local target=$1
  log "  [$target] провокация запуска подозрительного процесса (xmrig)"
  run_or_show "ssh '$target' bash -s <<'REMOTE'
cp /bin/sleep /tmp/xmrig_exp
nohup /tmp/xmrig_exp 5 >/dev/null 2>&1 &
PID=\$!
sleep 6
kill \$PID 2>/dev/null || true
rm -f /tmp/xmrig_exp
REMOTE"
  log "  [$target] подозрительный процесс провоцирован и убран"
}

#------------------------------------------------------------------
# 6) Privileged process: запуск нового PID c EUID=0
#    linux_proc видит новый pid в privileged_uids=[0]
#    → privileged_process_started
#------------------------------------------------------------------
provoke_privileged_proc() {
  local target=$1
  log "  [$target] провокация запуска привилегированного процесса"
  # Запускаем короткий sleep в отдельной shell, отделённый от ssh-shell-pid
  run_or_show "ssh '$target' 'nohup bash -c \"sleep 3\" >/dev/null 2>&1 & disown'"
  log "  [$target] привилегированный процесс запущен"
}

#------------------------------------------------------------------
# Dispatcher
#------------------------------------------------------------------
run_kind_on_target() {
  local target=$1
  local kind=$2
  case $kind in
    failed_logins)   provoke_failed_logins "$target";;
    remote_login)    provoke_remote_login "$target";;
    file_modified)   provoke_file_modified "$target";;
    iptables_rule)   provoke_iptables_rule "$target";;
    malware_process) provoke_malware_process "$target";;
    privileged_proc) provoke_privileged_proc "$target";;
    *) echo "unknown kind: $kind"; exit 3;;
  esac
}

KIND_LIST=()
if [[ "$KIND" == "all" ]]; then
  KIND_LIST=(failed_logins remote_login file_modified iptables_rule malware_process privileged_proc)
else
  IFS=',' read -ra KIND_LIST <<< "$KIND"
fi

log "============================================"
log "experiment_id = $EXPERIMENT_ID"
log "targets       = ${TARGET_LIST[*]}"
log "kinds         = ${KIND_LIST[*]}"
log "count         = $COUNT"
log "dry_run       = $DRY_RUN"
log "============================================"

for iter in $(seq 1 "$COUNT"); do
  log ""
  log "=== итерация $iter / $COUNT ==="
  for target in "${TARGET_LIST[@]}"; do
    for kind in "${KIND_LIST[@]}"; do
      run_kind_on_target "$target" "$kind"
    done
  done
done

log ""
log "============================================"
log "DONE. По журналам узлов:"
log "  ssh <host> 'journalctl -u mdrj-scenario2 -n 50 --no-pager | grep -i \"event_kind\\|admin_login\\|critical_file\\|iptables\\|known_malicious\\|privileged\"'"
log "  curl http://<host>:9002/dag | jq '.[-20:]'"
log "============================================"
