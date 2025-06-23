#!/bin/bash

# 콘솔에도 출력 (stdout)
echo "[psad trigger] Attack detected from $1 at $(date)" >> /var/log/psad/psad_custom_alert.log

# (필요시 화면에도 출력 - 단, systemd 서비스일 땐 이건 보통 안 뜬다.)
echo "[psad trigger] Attack detected from $1 at $(date)"

echo "PSAD 이상행동 감지!" | nc -N 192.168.55.8 9999

#/etc/psad/askable_notify.sh
