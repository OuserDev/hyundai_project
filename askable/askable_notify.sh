#!/bin/bash

# 인자 파싱 (예: --ip 192.168.55.8)
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --ip) ATTACKER_IP="$2"; shift ;;
    esac
    shift
done

# 로그 및 메시지 출력
if [[ -n "$ATTACKER_IP" ]]; then
    if [[ "$ATTACKER_IP" == 127.0.0.* ]]; then
        echo "[psad trigger] 내부 루프백 주소 감지됨 (무시): $ATTACKER_IP" >> /var/log/psad/psad_custom_alert.log
        exit 0
    fi
    echo "[psad trigger] Attack detected from $ATTACKER_IP at $(date)" >> /var/log/psad/psad_custom_alert.log
    echo "[psad trigger] Attack detected from $ATTACKER_IP at $(date)"
    echo "[PSAD] 네트워크 이상행동 탐지: $ATTACKER_IP" | nc -N 192.168.55.8 9999
else
    echo "[psad trigger] 공격자 IP를 찾을 수 없습니다." >> /var/log/psad/psad_custom_alert.log
fi
