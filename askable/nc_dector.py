import streamlit as st
import socket
import multiprocessing
import subprocess
import psutil
import re
import datetime

#테스팅을 별로 안해봐서 동작이 이상할 수 있음 그래도 인터페이스에 합치는 것은 무리 없을 걸로 생각

LISTEN_PORT = 9999
# 로그 위치는 자동화에 따라 적당히 추가 해줄것.
# 단 다른 로그 파일과 다르게 한 로그 파일 내부에 타임 스탬프 찍어서 보존하는 것을 표준으로 함
LOG_FILE = "/var/log/askable_event.log"

# 리스너 함수 (별도 프로세스에서 실행)
#소켓 에러 무척 잘남 -> 에러가 발생했을 시
# sudo lsof -i :9999, 혹은 sudo lsof -i :8502로 체크한 후
# kill -9 PID를 해서 죽인 후 재시작하면 잘됨

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
# 수신 메시지 형식은
# [프로토콜] 키워드: 공격자 ip로 구성
# [fail2ban] 브루트 포스 탐지: 192.168.55.3 on sshd

# [PSAD] 스캐닝 탐지: 192.168.55.3
def process_message(message):
    # fail2ban 메시지
    m1 = re.search(r'\[fail2ban\] 브루트 포스 탐지: ([\d\.]+) on (\w+)', message)
    if m1:
        ip = m1.group(1)
        service = m1.group(2)
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
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{now}] Source={source} IP={ip}"
    if service:
        log_line += f" Service={service}"
    with open(LOG_FILE, "a") as f:
        f.write(log_line + "\n")

# --- UI ---
st.set_page_config(page_title="Askable NC Listener", page_icon="🌐")
st.title("🌐 Askable 네트워크 이벤트 수신 시스템")

if "msg_list" not in st.session_state:
    st.session_state.msg_list = []
if "is_listening" not in st.session_state:
    st.session_state.is_listening = False
if "processed_events" not in st.session_state:
    st.session_state.processed_events = []

# 리스너 시작 버튼
if st.button("🎙️ 리스너 시작", disabled=st.session_state.is_listening):
    kill_process_using_port(LISTEN_PORT)
    queue = multiprocessing.Queue()
    p = multiprocessing.Process(target=socket_listener, args=(queue, LISTEN_PORT))
    p.start()

    st.session_state.listener_process = p
    st.session_state.listener_queue = queue
    st.session_state.is_listening = True
    st.success("✅ 리스너 시작됨")

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
    for e in reversed(st.session_state.processed_events[-20:]):
        st.success(e)
else:
    st.info("탐지된 이벤트가 아직 없습니다.")

# 포트스캔 실행
if st.button("🛰️ 포트 스캔 활성화"):
    try:
        result = subprocess.run(["ansible-playbook", "portscan.yml"], check=True, capture_output=True, text=True)
        st.success("✅ 포트 스캔 완료!")
        st.code(result.stdout)
    except subprocess.CalledProcessError as e:
        st.error("❌ 포트 스캔 실패!")
        st.code(e.stderr)

# SSH 실패 유발 버튼
if st.button("🚫 SSH 실패 유발"):
    try:
        result = subprocess.run(["ansible-playbook", "ssh_fail.yml"], check=True, capture_output=True, text=True)
        st.success("✅ SSH 실패 시도 완료!")
        st.code(result.stdout)
    except subprocess.CalledProcessError as e:
        st.error("❌ SSH 실패 시도 실패!")
        st.code(e.stderr)

# 새로고침 버튼
st.button("🔄 새로고침")
