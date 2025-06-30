STATE_FILE="/tmp/apache_log_state"

echo "[INFO] Web 로그 모니터링 데몬 시작됨"

while true; do
    # 마지막 읽은 줄 번호 가져오기
    if [ -f "$STATE_FILE" ]; then
        LAST_LINE=$(cat "$STATE_FILE")
    else
        LAST_LINE=0
    fi

    # 현재 총 줄 수 계산
    CURRENT_LINE=$(wc -l < "$LOGFILE")

    echo "[DEBUG] 현재 줄: $CURRENT_LINE, 이전 줄: $LAST_LINE"

    # 새로 추가된 로그만 처리
    if [ "$CURRENT_LINE" -gt "$LAST_LINE" ]; then
        tail -n $(($CURRENT_LINE - $LAST_LINE)) "$LOGFILE" | while read line; do
            echo "[TRACE] $line"
            if echo "$line" | grep -q "SQL_INJECTION"; then
                ATTACKER_IP=$(echo "$line" | grep -oP 'client_ip=\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || echo "$line" | grep -oP 'client: \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
                echo "[ALERT] SQL Injection 탐지됨 - IP: $ATTACKER_IP"
                echo "[`hostname`] [WebMonitor] SQL Injection 탐지: $ATTACKER_IP" | nc -N "$NC_SERVER" "$NC_PORT"
            elif echo "$line" | grep -q "File upload - Disk usage"; then
                echo "[WARN] 디스크 사용량 경고 발생"
                echo "[`hostname`] [WebMonitor] 디스크 용량 경고 발생" | nc -N "$NC_SERVER" "$NC_PORT"
            fi
        done
        echo "$CURRENT_LINE" > "$STATE_FILE"
    else
        echo "[INFO] 새로운 로그 없음"
    fi

    echo "[INFO] 3초 대기 중..."
    sleep 3
done
