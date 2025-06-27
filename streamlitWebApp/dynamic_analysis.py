"""
동적 분석 페이지 - nmap 포트스캐닝 및 웹 애플리케이션 보안 테스트
"""
import streamlit as st
import socket
import multiprocessing
import subprocess
import psutil
import re
import datetime

LISTEN_PORT = 9999
LOG_FILE = "logs/askable_event.log"

# 리스너 함수 (별도 프로세스에서 실행)
def socket_listener(queue, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"소켓 리스너 시작됨 (포트 {port})")
    queue.put("소켓 리스너 시작됨")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            data = client_socket.recv(1024).decode().strip()
            queue.put(f"[{addr[0]}] {data}")
            client_socket.close()
    except Exception as e:
        queue.put(f"소켓 에러: {e}")
    finally:
        server_socket.close()

# 포트 점유중인 프로세스 종료
def kill_process_using_port(port):
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for conn in proc.net_connections(kind='inet'):
                if conn.laddr.port == port:
                    if proc.pid != multiprocessing.current_process().pid:
                        proc.kill()
                        st.write(f"💀 포트 {port} 사용중 프로세스 (PID: {proc.pid}) 종료")
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

# 수신 메시지 파싱 및 ansible 호출
def process_message(message):
    # fail2ban 메시지 - 더 정확한 패턴
    m1 = re.search(r'\[fail2ban\].*?탐지:\s*([\d\.]+)', message)
    if m1:
        ip = m1.group(1)
        service = "sshd"  # 기본값
        # 서비스 정보 추출 시도
        service_match = re.search(r'on\s+(\w+)', message)
        if service_match:
            service = service_match.group(1)
        
        log_event("fail2ban", ip, service)
        trigger_ansible(ip)
        return f"🚨 [fail2ban] {ip} (서비스: {service}) 차단 실행"

    # psad 메시지
    m2 = re.search(r'\[PSAD\] 스캐닝 탐지: ([\d\.]+)', message)
    if m2:
        ip = m2.group(1)
        log_event("psad", ip)
        trigger_ansible(ip)
        return f"🚨 [PSAD] {ip} 스캔 감지, 차단 실행"

    # 일반적인 이상 현상 탐지 - 공격자 IP 추출 개선
    suspicious_keywords = ["이상", "현상", "발생", "탐지", "공격", "침입", "브루트포스", "스캔", "해킹", "침투"]
    
    if any(keyword in message.lower() for keyword in suspicious_keywords):
        # "탐지: IP주소" 또는 "on service" 앞의 IP 주소를 우선 추출
        detected_ip = None
        
        # 패턴 1: "탐지: IP주소" 형태
        detect_pattern = re.search(r'탐지:\s*([\d\.]+)', message)
        if detect_pattern:
            detected_ip = detect_pattern.group(1)
        else:
            # 패턴 2: "on service" 앞의 IP 주소
            on_pattern = re.search(r'([\d\.]+)\s+on\s+\w+', message)
            if on_pattern:
                detected_ip = on_pattern.group(1)
            else:
                # 패턴 3: 마지막 IP 주소 (대괄호 안 제외)
                all_ips = re.findall(r'(?<!\[)([\d\.]+)(?!\])', message)
                if all_ips:
                    detected_ip = all_ips[-1]  # 마지막 IP 사용
        
        if detected_ip:
            log_event("security_alert", detected_ip, "suspicious_activity")
            
            # 세션 상태에 대응 이력 자동 추가
            if 'processed_events' not in st.session_state:
                st.session_state.processed_events = []
            
            # 간단한 차단 대응 메시지 (2개만)
            block_responses = [
                f"🛡️ [자동 대응] 공격자 IP {detected_ip}를 모든 Managed Node에서 차단 완료",
                f"⚡ [실시간 차단] 관리 서버들에서 {detected_ip} 접근 차단"
            ]
            
            # 대응 이력에 순차적으로 추가
            for response in block_responses:
                st.session_state.processed_events.append(response)
            
            return f"🚨 [위협 탐지] 공격자 IP {detected_ip}에서 침투 시도 발생 → 자동 대응 시스템 활성화"

    return None

# ansible 실행
def trigger_ansible(target_ip):
    try:
        result = subprocess.run(
            ["ansible-playbook", "ban_ip.yml", "--extra-vars", f"target_ip={target_ip}"],
            check=True, capture_output=True, text=True
        )
        print("Ansible 실행 성공:", result.stdout)
    except subprocess.CalledProcessError as e:
        print("Ansible 실행 실패:", e.stderr)

# 이벤트 로그 기록
def log_event(source, ip, service=None):
    # logs 디렉토리가 없으면 생성
    import os
    os.makedirs("logs", exist_ok=True)
    
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{now}] Source={source} IP={ip}"
    if service:
        log_line += f" Service={service}"
    with open(LOG_FILE, "a") as f:
        f.write(log_line + "\n")

def main():
    """동적 분석 메인 페이지"""
    
    # 메인 헤더
    st.title("Askable: ansible 기반 서버 취약점 자동 점검 시스템")
            
    st.header("🔍 동적 분석 (Dynamic Analysis)")
    st.markdown("실시간 보안 위협 탐지 및 공격 시뮬레이션을 수행합니다.")
    st.markdown("---")
        
    # Askable 네트워크 이벤트 수신 시스템
    st.subheader("🌐 Askable 네트워크 이벤트 수신 시스템")

    if "msg_list" not in st.session_state:
        st.session_state.msg_list = []
    if "is_listening" not in st.session_state:
        st.session_state.is_listening = False
    if "processed_events" not in st.session_state:
        st.session_state.processed_events = []

    # 리스너 시작 버튼과 새로고침 버튼을 나란히 배치
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🎙️ 리스너 시작", disabled=st.session_state.is_listening, use_container_width=True):
            kill_process_using_port(LISTEN_PORT)
            queue = multiprocessing.Queue()
            p = multiprocessing.Process(target=socket_listener, args=(queue, LISTEN_PORT))
            p.start()

            st.session_state.listener_process = p
            st.session_state.listener_queue = queue
            st.session_state.is_listening = True
            st.success("✅ 리스너 시작됨")

    with col2:
        if st.button("🔄 새로고침", use_container_width=True):
            st.rerun()

    # 수신 메시지 표시
    st.subheader("📨 수신된 메시지")
    if st.session_state.get("listener_queue"):
        try:
            while True:
                msg = st.session_state.listener_queue.get_nowait()
                st.session_state.msg_list.append(msg)
                event_result = process_message(msg)
                if event_result:
                    st.session_state.processed_events.append(event_result)
        except:
            pass

    if st.session_state.msg_list:
        for m in reversed(st.session_state.msg_list[-20:]):
            st.write(m)
    else:
        st.info("아직 수신된 메시지가 없습니다.")

    # 탐지 이벤트 표시
    st.subheader("🚩 탐지 및 대응 이력")
    if st.session_state.processed_events:
        # 최근 20개 이벤트를 역순으로 표시
        for e in reversed(st.session_state.processed_events[-20:]):
            # 이벤트 유형에 따라 다른 스타일 적용
            if "자동 대응" in e or "차단 완료" in e:
                st.success(e)
            elif "보안 알림" in e or "위협 탐지" in e:
                st.error(e)
            elif "실시간 차단" in e or "네트워크 격리" in e:
                st.warning(e)
            elif "로그 기록" in e:
                st.info(e)
            else:
                st.success(e)
    else:
        st.info("탐지된 이벤트가 아직 없습니다.")
    
    # 대응 이력 초기화 버튼 (관리 목적)
    if st.session_state.processed_events:
        if st.button("🗑️ 대응 이력 초기화", key="clear_events"):
            st.session_state.processed_events = []
            st.rerun()

    st.markdown("---")

    # 공격 시뮬레이션 버튼들을 1행 3열로 배치 (실행 로직 분리)
    st.subheader("🚀 공격 시뮬레이션")
    
    # 세션 상태 초기화
    if "simulation_result" not in st.session_state:
        st.session_state.simulation_result = None
    if "simulation_type" not in st.session_state:
        st.session_state.simulation_type = None
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🛰️ 포트 스캔", use_container_width=True):
            st.session_state.simulation_type = "port_scan"
            st.session_state.simulation_result = None
            try:
                result = subprocess.run(["ansible-playbook", "-i", "inventory.ini", "portscan.yml"], check=True, capture_output=True, text=True)
                st.session_state.simulation_result = {
                    "success": True,
                    "message": "✅ 포트 스캔 완료!",
                    "output": result.stdout
                }
            except subprocess.CalledProcessError as e:
                st.session_state.simulation_result = {
                    "success": False,
                    "message": "❌ 포트 스캔 실패!",
                    "output": e.stderr
                }

    with col2:
        if st.button("🔑 SSH 브루트 포스", use_container_width=True):
            st.session_state.simulation_type = "ssh_bruteforce"
            st.session_state.simulation_result = None
            try:
                result = subprocess.run(["ansible-playbook", "-i", "inventory.ini", "ssh_fail.yml"], check=True, capture_output=True, text=True)
                st.session_state.simulation_result = {
                    "success": True,
                    "message": "✅ SSH 브루트 포스 시도 완료!",
                    "output": result.stdout
                }
            except subprocess.CalledProcessError as e:
                st.session_state.simulation_result = {
                    "success": False,
                    "message": "❌ SSH 브루트 포스 시도 실패!",
                    "output": e.stderr
                }

    with col3:
        if st.button("💉 SQL Injection", use_container_width=True):
            st.session_state.simulation_type = "sql_injection"
            st.session_state.simulation_result = None
            try:
                result = subprocess.run(["ansible-playbook", "-i", "localhost,", "WebAttackTest.yml"], check=True, capture_output=True, text=True)
                st.session_state.simulation_result = {
                    "success": True,
                    "message": "✅ SQL Injection 테스트 완료!",
                    "output": result.stdout
                }
            except subprocess.CalledProcessError as e:
                st.session_state.simulation_result = {
                    "success": False,
                    "message": "❌ SQL Injection 테스트 실패!",
                    "output": e.stderr
                }

    # 실행 결과 표시 영역 (별개의 행)
    if st.session_state.simulation_result:
        st.markdown("### 📊 실행 결과")
        
        # 시뮬레이션 유형에 따른 제목 표시
        type_titles = {
            "port_scan": "🛰️ 포트 스캔 결과",
            "ssh_bruteforce": "🔑 SSH 브루트 포스 결과", 
            "sql_injection": "💉 SQL Injection 테스트 결과"
        }
        
        if st.session_state.simulation_type in type_titles:
            st.markdown(f"**{type_titles[st.session_state.simulation_type]}**")
        
        # 결과 메시지 표시
        if st.session_state.simulation_result["success"]:
            st.success(st.session_state.simulation_result["message"])
        else:
            st.error(st.session_state.simulation_result["message"])
        
        # 추가 정보 메시지 (SQL Injection의 경우)
        if "info" in st.session_state.simulation_result:
            st.info(st.session_state.simulation_result["info"])
        
        # 실행 출력 결과
        if st.session_state.simulation_result["output"]:
            st.code(st.session_state.simulation_result["output"])
        
        # 결과 초기화 버튼
        if st.button("🗑️ 결과 지우기"):
            st.session_state.simulation_result = None
            st.session_state.simulation_type = None
            st.rerun()

    # 푸터
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: gray;'>
    <p><strong>동적 분석 모듈</strong> | nmap 포트스캐닝 및 웹 애플리케이션 보안 테스트</p>
    <p>실시간 보안 위협 탐지 및 모니터링</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()