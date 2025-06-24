import streamlit as st
import pandas as pd
import json
import time
import os
import queue
import glob
import re
import math
from datetime import datetime, timedelta

from modules.history_manager import render_sidebar_with_history, show_analysis_report
from modules.inventory_handler import parse_inventory_file, save_inventory_file
from modules.playbook_manager import save_generated_playbook, execute_ansible_playbook, generate_task_filename, generate_playbook_tasks
from modules.input_utils import parse_play_recap

# --- 페이지 설정  ---
st.set_page_config(
    page_title="Askable: Ansible 기반 취약점 자동 점검 시스템",
    page_icon="🔒",
    layout="wide"
)

# --- 관리자 계정 정보 (여기서 아이디와 비밀번호를 수정하세요) ---
ADMIN_USERNAME = "admin" # 관리자
ADMIN_PASSWORD = "password"
GUEST_USERNAME = "guest" # 일반유저
GUEST_PASSWORD = "password"

# --- 함수 정의 (모두 전역 범위로 이동) ---
@st.cache_data
def load_json_config(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        st.error(f"❌ {filename} 파일을 찾을 수 없습니다.")
        return None
    except json.JSONDecodeError:
        st.error(f"❌ {filename} 파일 형식이 올바르지 않습니다.")
        return None


# --- 로그인 UI를 렌더링하는 함수 ---
def render_login_form():
    st.markdown("<h1 style='text-align: center;'>Askable: 취약점 점검 시스템</h1>", unsafe_allow_html=True)
    st.markdown("---")
    
    col1, col2, col3 = st.columns([1.5, 2, 1.5])
    
    with col2:
        with st.form("login_form"):
            st.markdown("### 🔒 로그인")
            username = st.text_input("아이디 (Username)", placeholder="아이디를 입력하세요")
            password = st.text_input("비밀번호 (Password)", type="password", placeholder="비밀번호를 입력하세요")
            submitted = st.form_submit_button("로그인", use_container_width=True, type="primary")

            if submitted:
                if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                    st.query_params.clear()
                    st.success("Admin으로 로그인되었습니다! 잠시 후 메인 화면으로 이동합니다...")
                    st.session_state.role = 'admin'
                    time.sleep(1)
                    st.rerun()
                elif username == GUEST_USERNAME and password == GUEST_PASSWORD:
                    st.query_params.clear()
                    st.success("Guest로 로그인되었습니다! 잠시 후 분석 기록 화면으로 이동합니다...")
                    st.session_state.role = 'guest'
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("아이디 또는 비밀번호가 일치하지 않습니다.")
                    st.session_state.role = None

# ✨ 로그아웃 버튼을 렌더링하는 함수
def render_logout_button():
    """화면 우측 상단에 로그아웃 버튼을 생성"""
    _, col_logout = st.columns([0.9, 0.1])
    with col_logout:
        if st.button("로그아웃", key="..."): # key는 admin_logout 또는 guest_logout
            st.query_params.clear()
            for key in st.session_state.keys():
                del st.session_state[key]
            st.rerun()

# Guest 유저를 위한 화면을 렌더링하는 함수
def render_guest_view():
    """Guest 로그인 시 가장 최근의 '정상적인' 분석 기록만 표시"""
    st.title("최근 분석 기록")
    st.markdown("---")

    latest_valid_report = None
    
    try:
        # playbooks 디렉토리에서 모든 결과 폴더를 찾음
        report_dirs = glob.glob("playbooks/playbook_result_*")
        
        # ✨ 수정된 로직: 최신순으로 정렬하여 유효한 리포트를 찾을 때까지 반복
        for folder_path in sorted(report_dirs, key=os.path.getmtime, reverse=True):
            report_folder_name = os.path.basename(folder_path)
            timestamp_str = report_folder_name.replace("playbook_result_", "")
            
            # 해당 리포트의 결과 폴더와 로그 파일 경로를 확인
            results_path = os.path.join(folder_path, "results")
            log_path = os.path.join("logs", f"ansible_execute_log_{timestamp_str}.log")

            # 결과 폴더가 비어있지 않고, 로그 파일도 존재하면 유효한 리포트로 간주
            if os.path.exists(results_path) and os.listdir(results_path) and os.path.exists(log_path):
                latest_valid_report = report_folder_name
                break # 가장 최근의 유효한 리포트를 찾았으므로 반복 중단

    except Exception as e:
        st.error(f"분석 기록을 찾는 중 오류가 발생했습니다: {e}")
        latest_valid_report = None
    
    # 유효한 리포트를 찾은 경우에만 리포트 표시 함수 호출
    if latest_valid_report:
        # history_manager.py의 show_analysis_report 함수가 호출됨
        show_analysis_report(latest_valid_report, is_guest_view=True)
    else:
        # 유효한 리포트가 하나도 없을 경우 안내 메시지 표시
        col1, col2, col3 = st.columns([1, 3, 1])
        with col2:
            st.info("표시할 수 있는 정상적인 분석 기록이 없습니다. 관리자에게 문의 바랍니다.")

def calculate_selected_items(selected_checks, vulnerability_categories):
    """
    UI에서 실제로 체크된 항목의 개수만 정확히 계산하는 함수.
    """
    total_count = 0
    for service_name, selection_details in selected_checks.items():
        # 상세 선택 UI를 사용하는 서비스 (Server-Linux, PC-Linux 등)
        if isinstance(selection_details, dict):
            # '전체 선택'이 체크된 경우
            if selection_details.get("all"):
                total_count += vulnerability_categories.get(service_name, {}).get("count", 0)
            # 개별 항목이 선택된 경우
            else:
                categories = selection_details.get("categories", {})
                for category_items in categories.values():
                    for is_selected in category_items.values():
                        if is_selected:
                            total_count += 1
    
    return total_count


def render_main_app():
    """로그인 성공 후 표시될 메인 애플리케이션을 렌더링하는 함수 (Admin용)"""

    vulnerability_categories = load_json_config('vulnerability_categories.json')
    filename_mapping = load_json_config('filename_mapping.json')
    
    if vulnerability_categories is None or filename_mapping is None:
        st.error("설정 파일 로드에 실패하여 앱을 실행할 수 없습니다.")
        st.stop()

    render_sidebar_with_history(vulnerability_categories, filename_mapping)

    query_params = st.query_params
    selected_report = query_params.get("report", None)

    if selected_report:
        show_analysis_report(selected_report)
        st.stop()

    st.title("Askable: ansible 기반 서버 취약점 자동 점검 시스템 (관리자 모드)")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("### 📊 Streamlit Web UI")
        st.info("웹 대시보드 표시")
    with col2:
        st.markdown("### ⚙️ Control Node")
        st.success("Ansible 플레이북 동적 생성/실행")
    with col3:
        st.markdown("### 📄 Python Report Engine")
        st.warning("파싱 및 분석")
    st.markdown("---")

    st.header("🖥️ Managed Nodes 구성")
    st.subheader("📂 Inventory 파일 업로드")

    uploaded_file = st.file_uploader(
        "Ansible inventory.ini 파일을 업로드하세요", 
        type=['ini', 'txt'],
        help ="inventory.ini 파일을 업로드하면 자동으로 서버 목록을 생성합니다.",
        key="inventory_uploader"
        )

    if uploaded_file is not None:
        try:
            servers_info = parse_inventory_file(uploaded_file.read())
            st.success(f"✅ inventory.ini 파일이 성공적으로 로드되었습니다! ({len(servers_info)}개 서버)")
        except Exception as e:
            st.error(f"❌ inventory.ini 파일 파싱 중 오류가 발생했습니다: {str(e)}")
            servers_info = {}
    else:
        servers_info = {}
        st.warning("📂 inventory.ini 파일을 업로드해주세요.")

    st.subheader("🎯 대상 서버 선택")
    selected_servers = {}
    if servers_info:
        groups = {}
        for server_name, info in servers_info.items():
            group = info.get('group', 'default')
            if group not in groups:
                groups[group] = []
            groups[group].append((server_name, info))

        for group_name, group_servers in groups.items():
            st.markdown(f"**📁 {group_name.upper()} 그룹**")
            for server_name, info in group_servers:
                col1_server, col2_server, col3_server = st.columns([1, 2, 3])
                with col1_server:
                    selected = st.checkbox(server_name, key=f"server_{server_name}")
                    selected_servers[server_name] = selected
                with col2_server:
                    st.text(f"IP: {info.get('ip', 'N/A')}")
                with col3_server:
                    st.text(f"비고: {info.get('description', 'N/A')}")
            st.markdown("")
    else:
        st.info("📂 inventory.ini 파일을 먼저 업로드해주세요.")

    active_servers = [name for name, selected in selected_servers.items() if selected]
    if active_servers:
        st.success(f"✅ 선택된 서버: {', '.join(active_servers)}")
    else:
        st.warning("⚠️ 점검할 서버를 선택해주세요.")

    st.markdown("---")
    st.header("🔍 취약점 점검 체계")
    st.subheader("분석 종류 선택")

    col1_analysis, col2_analysis, col3_analysis = st.columns(3)
    with col1_analysis:
        static_enabled = st.checkbox("정적 분석 (Static Analysis)", help="**기준 가이드라인**: KISA 한국인터넷진흥원 2024.06 클라우드 취약점 점검 가이드", key="static_analysis_checkbox")
    with col2_analysis:
        st.checkbox("동적 분석 (Dynamic Analysis)", disabled=True, help="개발 중 - 추후 지원 예정", key="dynamic_analysis_checkbox")
    with col3_analysis:
        st.checkbox("네트워크 분석 (Network Analysis)", disabled=True, help="개발 중 - 추후 지원 예정", key="network_analysis_checkbox")

    selected_checks = {} # selected_checks를 미리 정의
    if static_enabled and active_servers and vulnerability_categories:
        st.subheader("📝 정적 분석 - 취약점 점검 항목 선택")
        available_services = set()
        for server_name in active_servers:
            if server_name in servers_info:
                available_services.update(servers_info[server_name].get("services", []))
        
        if not available_services:
            st.warning("⚠️ 선택된 서버에 점검 가능한 서비스가 없습니다.")
        else:
            col1_checks, col2_checks = st.columns(2)
            
            with col1_checks:
                st.markdown("**🖥️ 운영체제 관련**")
                
                if "Server-Linux" in available_services:
                    server_linux_data = vulnerability_categories.get("Server-Linux", {})
                    server_linux_count = server_linux_data.get("count", 0)
                    server_linux_all = st.checkbox(f"Server-Linux 전체 ({server_linux_count}개)", key="server_linux_all")
                    st.markdown("**세부 카테고리 선택:**")
                    selected_checks["Server-Linux"] = {"all": server_linux_all, "categories": {}}
                    if "subcategories" in server_linux_data:
                        for category, items in server_linux_data["subcategories"].items():
                            category_key_safe = re.sub(r'[^\uAC00-\uD7A3a-zA-Z0-9]', '', category)
                            category_selected = st.checkbox(f"{category} ({len(items)}개)", key=f"category_serverlinux_{category_key_safe}", value=server_linux_all)
                            if category_selected or server_linux_all:
                                with st.expander(f"{category} 세부 항목", expanded=server_linux_all):
                                    category_items = {}
                                    for item in items:
                                        item_key_safe = re.sub(r'[^\uAC00-\uD7A3a-zA-Z0-9]', '', item)
                                        item_selected = st.checkbox(item, key=f"item_serverlinux_{item_key_safe}", value=True if (server_linux_all or category_selected) else False)
                                        category_items[item] = item_selected
                                    selected_checks["Server-Linux"]["categories"][category] = category_items
                
                if "PC-Linux" in available_services:
                    st.markdown("**💻 PC-Linux 관련**")
                    pc_linux_data = vulnerability_categories.get("PC-Linux", {})
                    pc_linux_count = pc_linux_data.get("count", 0)
                    pc_linux_all = st.checkbox(f"PC-Linux 전체 ({pc_linux_count}개)", key="pc_linux_all")
                    selected_checks["PC-Linux"] = {"all": pc_linux_all, "categories": {}}
                    if "subcategories" in pc_linux_data:
                        st.markdown("**세부 카테고리 선택:**")
                        for category, items in pc_linux_data["subcategories"].items():
                            category_key_safe = re.sub(r'[^\uAC00-\uD7A3a-zA-Z0-9]', '', category)
                            category_selected = st.checkbox(f"{category} ({len(items)}개)", key=f"category_pclinux_{category_key_safe}", value=pc_linux_all)
                            if category_selected or pc_linux_all:
                                with st.expander(f"{category} 세부 항목"):
                                    category_items = {}
                                    for item in items:
                                        item_key_safe = re.sub(r'[^\uAC00-\uD7A3a-zA-Z0-9]', '', item)
                                        item_selected = st.checkbox(item, key=f"item_pclinux_{item_key_safe}", value=True if (pc_linux_all or category_selected) else False)
                                        category_items[item] = item_selected
                                    selected_checks["PC-Linux"]["categories"][category] = category_items
            
            with col2_checks:
                st.markdown("**💾 데이터베이스 & 웹서비스**")
                services_to_render = ["MySQL", "Apache", "Nginx", "PHP", "SQLite"]
                for service_name in services_to_render:
                    if service_name in available_services:
                        if service_name in vulnerability_categories and "subcategories" in vulnerability_categories[service_name]:
                            service_data = vulnerability_categories[service_name]
                            total_count = service_data.get("count", 0)
                            st.markdown(f"**{service_name} 관련**")
                            all_selected = st.checkbox(f"{service_name} 전체 ({total_count}개)", key=f"{service_name.lower()}_all")
                            st.markdown("**세부 카테고리 선택:**")
                            selected_checks[service_name] = {"all": all_selected, "categories": {}}
                            for category, items in service_data["subcategories"].items():
                                category_key_safe = re.sub(r'[^\uAC00-\uD7A3a-zA-Z0-9]', '', category)
                                category_selected = st.checkbox(f"{category} ({len(items)}개)", key=f"category_{service_name.lower()}_{category_key_safe}", value=all_selected)
                                if category_selected or all_selected:
                                    with st.expander(f"{category} 세부 항목"):
                                        category_items = {}
                                        for item in items:
                                            item_key_safe = re.sub(r'[^\uAC00-\uD7A3a-zA-Z0-9]', '', item)
                                            item_selected = st.checkbox(item, key=f"item_{service_name.lower()}_{category_key_safe}_{item_key_safe}", value=True if (all_selected or category_selected) else False)
                                            category_items[item] = item_selected
                                        selected_checks[service_name]["categories"][category] = category_items
                            st.markdown("---")

    st.markdown("---")
    st.header("🚀 Ansible 플레이북 실행")

    if 'playbook_generated' not in st.session_state:
        st.session_state.playbook_generated = False
    if 'playbook_path' not in st.session_state:
        st.session_state.playbook_path = ""
    if 'inventory_path' not in st.session_state:
        st.session_state.inventory_path = ""
    if 'playbook_tasks' not in st.session_state:
        st.session_state.playbook_tasks = []
    if 'selected_checks' not in st.session_state:
        st.session_state.selected_checks = {}
    if 'result_folder_path' not in st.session_state:
        st.session_state.result_folder_path = ""
    if active_servers and static_enabled and any(selected_checks.values()):
        if not st.session_state.playbook_generated:
            if st.button("🔍 취약점 점검을 위한 플레이북 생성", type="primary", use_container_width=True):
                with st.spinner("Ansible 플레이북 동적 생성 중..."):


                    # ✨ --- 디버깅 코드 추가 --- ✨
                    st.info("플레이북 생성 직전의 'selected_checks' 변수 내용을 확인합니다.")
                    st.json(selected_checks)
                    # ✨ -------------------- ✨

                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    result_folder_name = f"playbook_result_{timestamp}"
                    result_folder_path = os.path.join("playbooks", result_folder_name)
                    os.makedirs(result_folder_path, exist_ok=True)
                    os.makedirs(os.path.join(result_folder_path, "results"), exist_ok=True)  # 결과 하위 폴더도 미리 생성
                    
                    # 선택된 점검 항목에 따른 플레이북 태스크 생성
                    playbook_tasks = generate_playbook_tasks(selected_checks, filename_mapping, vulnerability_categories)
                    
                     # 백엔드 콘솔에 생성 정보 출력
                    print(f"\n{'='*80}")
                    print(f"📝 PLAYBOOK 생성 시작")
                    print(f"{'='*80}")
                    print(f"🎯 대상 서버: {active_servers}")
                    print(f"📋 선택된 점검 항목: {len(playbook_tasks)}개")
                    print(f"📁 결과 폴더: {result_folder_path}")
                    if playbook_tasks:
                        print("📄 포함될 파일들:")
                        for i, task in enumerate(playbook_tasks, 1):
                            print(f"   {i}. {task}")
                    print(f"{'='*80}")
                    
                    # 플레이북 파일로 저장 
                    playbook_path, playbook_filename, timestamp = save_generated_playbook(active_servers, playbook_tasks, result_folder_path)
                    # inventory 파일 저장 (결과 폴더 내에)
                    inventory_path = save_inventory_file(servers_info, active_servers, result_folder_path)
                    
                    # 백엔드 콘솔에 저장 완료 메시지
                    print(f"✅ 플레이북 저장 완료: {playbook_path}")
                    print(f"✅ 인벤토리 저장 완료: {inventory_path}")
                    print(f"📁 결과가 저장될 위치: {result_folder_path}/results/")
                    print(f"{'='*80}\n")
                    
                    # 세션 상태에 저장
                    st.session_state.playbook_generated = True
                    st.session_state.playbook_path = playbook_path
                    st.session_state.inventory_path = inventory_path
                    st.session_state.playbook_tasks = playbook_tasks
                    st.session_state.selected_checks = selected_checks
                    st.session_state.result_folder_path = result_folder_path
                    st.session_state.timestamp = timestamp
                    time.sleep(1)
                    st.rerun()
        
        if st.session_state.playbook_generated:
            st.success("✅ 플레이북 생성 및 저장 완료!")
            total_checks = calculate_selected_items(st.session_state.selected_checks, vulnerability_categories)
            num_tasks = len(st.session_state.playbook_tasks)
            total_seconds = num_tasks * 8

            if total_seconds > 0:
                total_minutes = total_seconds // 60
                remaining_seconds = total_seconds % 60
                rounded_seconds = math.ceil(remaining_seconds / 10.0) * 10
                if rounded_seconds >= 60:
                    total_minutes += 1
                    rounded_seconds = 0
                if total_minutes > 0 and rounded_seconds > 0:
                    estimated_time_str = f"약 {total_minutes}분 {rounded_seconds}초"
                elif total_minutes > 0:
                    estimated_time_str = f"약 {total_minutes}분"
                else:
                    estimated_time_str = f"약 {rounded_seconds}초"
            else:
                estimated_time_str = "0초"
            
            playbook_info = {
                "대상 서버": active_servers,
                "총 점검 항목": f"{total_checks}개",
                "점검 서비스": list(st.session_state.selected_checks.keys()),
                "생성된 플레이북": os.path.basename(st.session_state.playbook_path),
                "저장 경로": st.session_state.playbook_path,
                "inventory 파일": st.session_state.inventory_path,
                "결과 저장 폴더": f"{st.session_state.result_folder_path}/results/",
                "생성 시간": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "예상 소요 시간": estimated_time_str  # 🎯 계산된 값으로 교체
            }
            st.json(playbook_info)
            
            st.warning("⚠️ 실제 서버에 변경 사항이 적용됩니다!")
            if st.button("▶️ 실행 시작", type="secondary", use_container_width=True):
                st.subheader("🖥️ 실행 중인 Ansible 명령어")
                cmd_text = f"ansible-playbook -i {st.session_state.inventory_path} {st.session_state.playbook_path} --limit target_servers -v"
                st.code(cmd_text)
                
                st.subheader("📄 실시간 실행 로그")
                output_container = st.empty()
                status_text = st.empty()
                try:
                    print(f"\n🔥 실제 실행 모드로 Ansible 플레이북 실행을 시작합니다...")
                    output_queue, thread = execute_ansible_playbook(
                        st.session_state.playbook_path, 
                        st.session_state.inventory_path, 
                        active_servers,
                        st.session_state.result_folder_path,
                        st.session_state.timestamp
                    )

                    # 로그 파일 정보 표시
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    log_filename = f"ansible_execute_log_{timestamp}.log"
                    st.info(f"📄 실행 로그가 다음 위치에 저장됩니다: `logs/{log_filename}`")
                
                    
                    displayed_logs = []
                    finished = False
                    result_summary = {"성공한 태스크": 0, "변경된 설정": 0, "실패한 태스크": 0, "접근 불가 서버": 0}  # 초기값 추가

                    while not finished:
                        try:
                            msg_type, content = output_queue.get(timeout=1)

                            if msg_type == 'output' and content and content.strip():
                                displayed_logs.append(content.strip())
                                log_text = '\n'.join(displayed_logs[-100:])
                                display_text = log_text + '\n' + '─' * 50 + f' (실시간 업데이트 {len(displayed_logs)}) ' + '─' * 50
                                
                                # 스크롤 가능한 스타일링된 컨테이너로 표시
                                output_container.markdown(f"""
                                <div style="
                                    background-color: #0e1117;
                                    border: 1px solid #262730;
                                    border-radius: 5px;
                                    padding: 10px;
                                    font-family: 'Courier New', monospace;
                                    font-size: 11px;
                                    color: #fafafa;
                                    max-height: 400px;
                                    overflow-y: auto;
                                    white-space: pre-wrap;
                                    word-wrap: break-word;
                                ">
                                {display_text.replace('<', '&lt;').replace('>', '&gt;')}
                                </div>
                                """, unsafe_allow_html=True)
                            elif msg_type == 'finished':
                                finished = True
                                if content == 0:
                                    st.success("🎉 Ansible 플레이북 실행 완료!")
                                    st.success(f"📄 전체 실행 로그가 `logs/{log_filename}`에 저장되었습니다.")
                                    st.success(f"📁 점검 결과 파일들이 `{st.session_state.result_folder_path}/results/`에 저장되었습니다.")
                                    print("🎉 스트림릿 UI에서도 실행 완료 확인됨")
                                    # PLAY RECAP 파싱하여 실제 결과 표시
                                    result_summary = parse_play_recap(displayed_logs)
                                else:
                                    st.error(f"❌ 실행 실패 (종료 코드: {content})")
                                    print(f"❌ 스트림릿 UI에서도 실행 실패 확인됨 (코드: {content})")
                                    # 실패해도 가능한 결과는 파싱
                                    result_summary = parse_play_recap(displayed_logs)
                            elif msg_type == 'error':
                                st.error(f"❌ 실행 오류: {content}")
                                print(f"❌ 스트림릿 UI에서도 오류 확인됨: {content}")
                                finished = True
                                result_summary = parse_play_recap(displayed_logs)
                        except queue.Empty:
                            continue
                    thread.join(timeout=5)
                except Exception as e:
                    error_msg = f"실행 중 오류 발생: {str(e)}"
                    st.error(f"❌ {error_msg}")
                    print(f"❌ [STREAMLIT ERROR] {error_msg}")
                    result_summary = {"성공한 태스크": 0, "변경된 설정": 0, "실패한 태스크": 0, "접근 불가 서버": 0}
                    
                # 최종 실행 결과 요약
                st.subheader("📊 실행 결과 요약")
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("✅ 성공", f"{result_summary['성공한 태스크']}개")
                with col2:
                    st.metric("🔄 변경", f"{result_summary['변경된 설정']}개")
                with col3:
                    st.metric("❌ 실패", f"{result_summary['실패한 태스크']}개")
                with col4:
                    st.metric("🚫 접근불가", f"{result_summary['접근 불가 서버']}개")
                    
                # 서버별 상세 결과 표시 (추가 기능)
                
                if result_summary.get("서버 상세"):
                    st.subheader("🖥️ 서버별 상세 결과")
                
                    for server_name, stats in result_summary["서버 상세"].items():
                        with st.expander(f"📍 {server_name} 서버 결과"):
                            col1, col2, col3, col4, col5 = st.columns(5)
                            
                            with col1:
                                st.metric("성공", stats.get('ok', 0), delta=None)
                            with col2:
                                st.metric("변경", stats.get('changed', 0), delta=None)
                            with col3:
                                st.metric("실패", stats.get('failed', 0), delta=None)
                            with col4:
                                st.metric("접근불가", stats.get('unreachable', 0), delta=None)
                            with col5:
                                st.metric("건너뛴", stats.get('skipped', 0), delta=None)

                    # 전체 성공률 표시 (추가 기능)
                    if result_summary["성공한 태스크"] > 0 or result_summary["실패한 태스크"] > 0:
                        total_tasks = result_summary["성공한 태스크"] + result_summary["실패한 태스크"]
                        success_rate = (result_summary["성공한 태스크"] / total_tasks) * 100 if total_tasks > 0 else 0
                        
                        st.subheader("📈 전체 성공률")
                        st.progress(success_rate / 100)
                        st.write(f"**{success_rate:.1f}%** ({result_summary['성공한 태스크']}/{total_tasks} 태스크 성공)")

                    # 문제가 있는 경우 경고 표시
                    if result_summary["실패한 태스크"] > 0:
                        st.error(f"⚠️ {result_summary['실패한 태스크']}개의 태스크가 실패했습니다. 로그를 확인해주세요.")

                    if result_summary["접근 불가 서버"] > 0:
                        st.warning(f"🔌 {result_summary['접근 불가 서버']}개의 서버에 접근할 수 없습니다. 네트워크 연결을 확인해주세요.")
            
            # 실행 후 초기화 버튼        
            if st.button("🔄 새로운 점검 시작 (현재 세션을 초기화하고 처음부터 다시)", use_container_width=True):
                # 세션 상태 초기화
                st.session_state.playbook_generated = False
                st.session_state.playbook_path = ""
                st.session_state.inventory_path = ""
                st.session_state.playbook_tasks = []
                st.session_state.selected_checks = {}
                st.session_state.result_folder_path = ""
                st.rerun()    
            st.markdown("---")

    else:
        st.error("❌ 서버와 점검 항목을 선택한 후 실행해주세요.")
        
    # 푸터
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: gray;'>
    <p><strong>Team 2</strong> | Ansible 기반 서버 취약점 자동 점검 및 보고서 생성 시스템</p>
    <p>KISA 한국인터넷진흥원 2024.06 클라우드 취약점 점검 가이드 기반</p>
    </div>
    """, unsafe_allow_html=True)


# --- 메인 실행 로직 ---

# ✨ 세션 상태 키를 'role'로 변경하여 사용자 역할 관리
if "role" not in st.session_state:
    st.session_state.role = None

# ✨ 역할에 따라 다른 화면을 보여줌
if st.session_state.role == 'admin':
    render_logout_button()
    render_main_app()
elif st.session_state.role == 'guest':
    render_logout_button()
    render_guest_view()

else:
    # 로그인되지 않은 상태면 로그인 폼 표시
    render_login_form()