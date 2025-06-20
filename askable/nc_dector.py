import streamlit as st
import socket
import multiprocessing
import time
import subprocess

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

# --- Streamlit UI ---
st.set_page_config(page_title="Socket Listener Demo", page_icon="🌐")
st.title("🌐 소켓 기반 NC 리포트 수신 테스트")

LISTEN_PORT = 9999

if "listener_process" not in st.session_state:
    st.session_state.listener_process = None
if "msg_list" not in st.session_state:
    st.session_state.msg_list = []

if st.button("🎙️ 리스너 시작"):
    if st.session_state.listener_process is None or not st.session_state.listener_process.is_alive():
        st.session_state.queue = multiprocessing.Queue()
        p = multiprocessing.Process(target=socket_listener, args=(st.session_state.queue, LISTEN_PORT))
        p.start()
        st.session_state.listener_process = p
        st.success("✅ 리스너가 시작되었습니다.")
    else:
        st.warning("리스너가 이미 실행 중입니다.")

st.subheader("📨 수신된 메시지")

if "queue" in st.session_state:
    try:
        while True:
            msg = st.session_state.queue.get_nowait()
            st.session_state.msg_list.append(msg)
    except:
        pass

if st.session_state.msg_list:
    for m in reversed(st.session_state.msg_list[-20:]):
        st.write(m)
else:
    st.info("아직 수신된 메시지가 없습니다.")

# 포트 스캔 활성화 버튼
if st.button("🛰️ 포트 스캔 활성화"):
    try:
        result = subprocess.run(
            ["ansible-playbook", "portscan.yml"],
            check=True,
            capture_output=True,
            text=True
        )
        st.success("✅ 포트 스캔 완료!")
        st.code(result.stdout)
    except subprocess.CalledProcessError as e:
        st.error("❌ 포트 스캔 실패!")
        st.code(e.stderr)

# 새로고침 버튼
st.button("🔄 새로고침")
