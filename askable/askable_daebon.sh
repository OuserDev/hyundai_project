#!/bin/bash

LOGFILE="/var/log/localhost_error.log"
NC_SERVER="192.168.55.8"
NC_PORT="9999"

# 마지막 라인 저장 파일 (초기 없으면 0)
STATE_FILE="/tmp/apache_log_state"

# 마지막 읽은 줄 번호 가져오기
if [ -f "$STATE_FILE" ]; then
    LAST_LINE=$(cat "$STATE_FILE")
else
    LAST_LINE=0
fi

# 현재 총 줄 수 계산
CURRENT_LINE=$(wc -l < "$LOGFILE")

# 새로 추가된 로그만 처리
if [ "$CURRENT_LINE" -gt "$LAST_LINE" ]; then
    tail -n $(($CURRENT_LINE - $LAST_LINE)) "$LOGFILE" | while read line; do
        if echo "$line" | grep -q "SQL_INJECTION"; then
            # IP 파싱
            ATTACKER_IP=$(echo "$line" | grep -oP 'client \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
            echo "[`hostname`] [WebMonitor] SQL Injection 탐지: $ATTACKER_IP" | nc -N "$NC_SERVER" "$NC_PORT"
        elif echo "$line" | grep -q "File upload - Disk usage"; then
            echo "[`hostname`] [WebMonitor] 디스크 용량 경고 발생" | nc -N "$NC_SERVER" "$NC_PORT"
        fi
    done
    echo "$CURRENT_LINE" > "$STATE_FILE"
fi
