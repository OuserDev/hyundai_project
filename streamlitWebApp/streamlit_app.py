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
from modules.input_utils import count_selected_checks, parse_play_recap

# --- 페이지 설정  ---
st.set_page_config(
    page_title="Askable: Ansible 기반 취약점 자동 점검 시스템",
    page_icon="🔒",
    layout="wide"
)
st.markdown("""
<style>
    .main-title {
        text-align: center;
        font-size: 4rem;
        font-weight: bold;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #2E86C1 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        transform: skew(-5deg);
        margin-bottom: 0.5rem;
    }
    .sub-title {
        text-align: center;
        color: #566573;
        margin-bottom: 2rem;
        font-weight: 300;
    }
    .divider {
        border: none;
        height: 3px;
        background: linear-gradient(90deg, #2E86C1, #85C1E9, #2E86C1);
        margin: 2rem 0;
        border-radius: 2px;
    }
</style>
""", unsafe_allow_html=True)
st.markdown('<h1 class="main-title">Askable</h1>', unsafe_allow_html=True)
st.markdown('<p class="sub-title" style="font-size: 2rem">Ansible 기반 취약점 자동 점검 및 공격 탐지 시스템</p>', unsafe_allow_html=True)
st.markdown('<hr class="divider">', unsafe_allow_html=True)

# --- 관리자 계정 정보 (여기서 아이디와 비밀번호를 수정하세요) ---
ADMIN_USERNAME = "admin" # 관리자
ADMIN_PASSWORD = "admin"
GUEST_USERNAME = "guest" # 일반유저
GUEST_PASSWORD = "guest"

# --- 함수 정의 (모두 전역 범위로 이동) ---
@st.cache_data
def load_json_config(filename):
    """JSON 설정 파일을 로드합니다."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        st.error(f"❌ {filename} 파일을 찾을 수 없습니다.")
        return {}
    except json.JSONDecodeError:
        st.error(f"❌ {filename} 파일 형식이 올바르지 않습니다.")
        return {}

# --- 로그인 UI를 렌더링하는 함수 ---
def render_login_form():
    
    col1, col2, col3 = st.columns([1.5, 2, 1.5])
    
    with col2:
        with st.form("login_form"):
            st.markdown("### 🔒 Login")
            username = st.text_input("아이디 (Username)", placeholder="아이디를 입력하세요")
            password = st.text_input("비밀번호 (Password)", type="password", placeholder="비밀번호를 입력하세요")
            submitted = st.form_submit_button("로그인", use_container_width=True, type="primary")

            if submitted:
                if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                    st.query_params.clear()
                    st.success("Admin으로 로그인되었습니다! 잠시 후 메인 화면으로 이동합니다.")
                    st.session_state.role = 'admin'
                    time.sleep(1)
                    st.rerun()
                elif username == GUEST_USERNAME and password == GUEST_PASSWORD:
                    st.query_params.clear()
                    st.success("Guest로 로그인되었습니다! 잠시 후 분석 기록 화면으로 이동합니다.")
                    st.session_state.role = 'guest'
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("아이디 또는 비밀번호가 일치하지 않습니다.")
                    st.session_state.role = None

# Guest 유저를 위한 화면을 렌더링하는 함수
def render_guest_view():
    """Guest 로그인 시 가장 최근의 '정상적인' 분석 기록만 표시"""
    
    # 게스트도 사이드바를 볼 수 있도록 추가
    vulnerability_categories = load_json_config('vulnerability_categories.json')
    filename_mapping = load_json_config('filename_mapping.json')
    
    if vulnerability_categories and filename_mapping:
        render_sidebar_with_history(vulnerability_categories, filename_mapping)
    
    # 🆕 Guest 사용자가 사이드바에서 특정 리포트를 선택한 경우 처리
    query_params = st.query_params
    selected_report = query_params.get("report", None)
    
    if selected_report:
        # 선택된 리포트가 있으면 해당 리포트를 표시
        show_analysis_report(selected_report)
        return  # 함수 종료하여 아래 코드 실행 방지

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
                latest_valid_report = timestamp_str  # 여기를 수정
                break # 가장 최근의 유효한 리포트를 찾았으므로 반복 중단

    except Exception as e:
        st.error(f"분석 기록을 찾는 중 오류가 발생했습니다: {e}")
        latest_valid_report = None
    
    # 유효한 리포트를 찾은 경우에만 리포트 표시 함수 호출
    if latest_valid_report:
        # history_manager.py의 show_analysis_report 함수가 호출됨
        show_analysis_report(latest_valid_report)
    else:
        # 유효한 리포트가 하나도 없을 경우 안내 메시지 표시
        col1, col2, col3 = st.columns([1, 3, 1])
        with col2:
            st.info("표시할 수 있는 정상적인 분석 기록이 없습니다. 관리자에게 문의 바랍니다.")

def reset_playbook_session(reason="사용자 요청"):
    """플레이북 실행 관련 세션 상태를 초기화하는 함수"""
    print(f"\n{'='*60}")
    print(f"🔄 세션 상태 초기화 - {reason}")
    print(f"{'='*60}")
    
    # 기존 세션 상태 백업 (디버깅용)
    old_state = {
        'playbook_generated': st.session_state.get('playbook_generated', False),
        'playbook_path': st.session_state.get('playbook_path', ""),
        'result_folder_path': st.session_state.get('result_folder_path', ""),
    }
    
    if any(old_state.values()):
        print(f"📊 초기화 전 상태: {old_state}")
    
    # 세션 상태 초기화
    session_keys_to_reset = [
        'playbook_generated',
        'playbook_path', 
        'inventory_path',
        'playbook_tasks',
        'selected_checks',
        'result_folder_path',
        'timestamp'
    ]
    
    for key in session_keys_to_reset:
        if key in st.session_state:
            if key == 'playbook_tasks' or key == 'selected_checks':
                st.session_state[key] = {}
            elif key == 'playbook_generated':
                st.session_state[key] = False
            else:
                st.session_state[key] = ""
    
    print(f"✅ 세션 초기화 완료")
    print(f"{'='*60}\n")
    
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

def sync_checkbox_states():
    """체크박스 상태 동기화 함수"""
    individual_states = {}
    category_states = {}
    
    for category, items in vulnerability_categories["Server-Linux"]["subcategories"].items():
        category_items = {}
        category_checked_count = 0
        
        for item in items:
            item_key = f"item_{item}"
            is_checked = st.session_state.get(item_key, False)
            category_items[item] = is_checked
            if is_checked:
                category_checked_count += 1
        
        individual_states[category] = category_items
        category_states[category] = (category_checked_count == len(items) and len(items) > 0)
    
    # 전체 상태 계산
    total_items = sum(len(items) for items in individual_states.values())
    checked_items = sum(sum(items.values()) for items in individual_states.values())
    all_checked = (checked_items == total_items and total_items > 0)
    
    return individual_states, category_states, all_checked

def render_main_app():
    """로그인 성공 후 표시될 메인 애플리케이션을 렌더링하는 함수 (Admin용)"""

    vulnerability_categories = load_json_config('vulnerability_categories.json')
    filename_mapping = load_json_config('filename_mapping.json')
    
    if vulnerability_categories is None or filename_mapping is None:
        st.error("설정 파일 로드에 실패하여 앱을 실행할 수 없습니다.")
        st.stop()

    render_sidebar_with_history(vulnerability_categories, filename_mapping)

    # 쿼리 파라미터 확인해서 분석 리포트 페이지 표시할지 결정
    query_params = st.query_params
    selected_report = query_params.get("report", None)
    selected_page = query_params.get("page", None)

    # 공격 탐지 페이지 라우팅
    if selected_page == "dynamic_analysis":
        try:
            import dynamic_analysis
            dynamic_analysis.main()
            st.stop()
        except ImportError:
            st.error("❌ dynamic_analysis.py 모듈을 찾을 수 없습니다.")

    # 스케줄링 페이지 라우팅
    if selected_page == "scheduling":
        try:
            import scheduling
            scheduling.main()
            st.stop()
        except ImportError:
            st.error("❌ scheduling.py 모듈을 찾을 수 없습니다.")
            # 스케줄링 모듈이 없을 경우 기본 안내
            st.info("💡 스케줄링 모듈은 추후 구현 예정입니다.")

    if selected_report:
        # 분석 리포트 페이지 표시
        show_analysis_report(selected_report)
        st.stop()  # 메인 페이지 렌더링 중단
            
    # 취약점 점검 체계 선택
    st.header("📋 취약점 점검 (Static Analysis)")
    st.markdown("""
    **KISA 한국인터넷진흥원 공식 취약점 점검 가이드라인 기반** - 77개 항목의 체계적인 취약점 진단으로 서버 보안을 강화하세요.""")
    st.markdown("---")

    # inventory.ini 파일 업로드 섹션
    st.subheader("🖥️ Managed Nodes 구성")

    # 파일 업로드 위젯
    uploaded_file = st.file_uploader(
        "📂 inventory.ini 파일을 업로드해주세요. (ansible_host ansible_user, ansible_become_pass 및 대상 Managed Node로의 SSH 공개키 사전 발급 필수)",
        type=['ini', 'txt'],
        help="inventory.ini 파일을 업로드하면 자동으로 서버 목록을 생성합니다"
    )

    # inventory 파일 처리
    if uploaded_file is not None:
        try:
            servers_info = parse_inventory_file(uploaded_file.read())
            st.success(f"✅ inventory.ini 파일이 성공적으로 로드되었습니다! ({len(servers_info)}개 서버)")
            
        except Exception as e:
            st.error(f"❌ inventory.ini 파일 파싱 중 오류가 발생했습니다: {str(e)}")
            servers_info = {}
    else:
        servers_info = {}

    # 서버 선택 섹션
    st.subheader("🎯 대상 서버 선택")
    selected_servers = {}

    if servers_info:
        # 그룹별로 서버 정리
        groups = {}
        for server_name, info in servers_info.items():
            group = info.get('group', 'default')
            if group not in groups:
                groups[group] = []
            groups[group].append((server_name, info))

        # 그룹별로 표시
        for group_name, group_servers in groups.items():
            st.markdown(f"**📁 {group_name.upper()} 그룹**")
            
            for server_name, info in group_servers:
                col1, col2, col3 = st.columns([1, 2, 3])
                
                with col1:
                    selected = st.checkbox(server_name, key=f"server_{server_name}")
                    selected_servers[server_name] = selected
                
                with col2:
                    st.text(f"IP: {info['ip']}")
                
                with col3:
                    st.text(f"비고: {info['description']}")
            
            st.markdown("")  # 그룹 간 간격
    else:
        st.info("📂 inventory.ini 파일을 먼저 업로드해주세요.")

    # 선택된 서버 표시
    active_servers = [name for name, selected in selected_servers.items() if selected]
    if active_servers:
        st.success(f"✅ 선택된 서버: {', '.join(active_servers)}")
    else:
        st.warning("⚠️ 점검할 서버를 선택해주세요.")

    st.markdown("---")

    # 취약점 점검 세부 설정 - 서버 선택 시에만 표시
    if active_servers and vulnerability_categories:
        st.subheader("📝 취약점 점검 항목 선택")
        
        # 🆕 분석 모드 선택 추가
        analysis_mode = st.radio(
            "분석 모드 선택:",
            ["🔄 모든 서버 동일 설정", "⚙️ 서버별 개별 설정"],
            index=0,
            horizontal=True,
            help="모든 서버에 같은 점검을 할지, 서버마다 다른 점검을 할지 선택하세요"
        )
        
        st.markdown("---")
        
        # 서비스별 점검 항목 선택
        selected_checks = {}
        
        if analysis_mode == "🔄 모든 서버 동일 설정":
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### 🖥️ 운영체제")
                
                # Server-Linux
                server_linux_all = st.checkbox("🐧 Server-Linux 전체 (36개)", key="server_linux_all")
                selected_checks["Server-Linux"] = {"all": server_linux_all, "categories": {}}
                
                if server_linux_all:
                    st.success("✅ Server-Linux 전체 36개 항목 선택됨")
                else:
                    with st.expander("📋 Server-Linux 세부 카테고리 선택"):
                        for category, items in vulnerability_categories["Server-Linux"]["subcategories"].items():
                            category_selected = st.checkbox(
                                f"{category} ({len(items)}개)", 
                                key=f"category_server_linux_{category}"
                            )
                            
                            if category_selected:
                                category_items = {}
                                for item in items:
                                    item_selected = st.checkbox(
                                        item, 
                                        key=f"item_server_linux_{item}", 
                                        value=True
                                    )
                                    category_items[item] = item_selected
                                selected_checks["Server-Linux"]["categories"][category] = category_items
                
                st.markdown("---")
                
                # PC-Linux
                pc_linux_all = st.checkbox("🖥️ PC-Linux 전체 (12개)", key="pc_linux_all")
                selected_checks["PC-Linux"] = {"all": pc_linux_all, "categories": {}}
                
                if pc_linux_all:
                    st.success("✅ PC-Linux 전체 12개 항목 선택됨")
                else:
                    with st.expander("📋 PC-Linux 세부 카테고리 선택"):
                        for category, items in vulnerability_categories["PC-Linux"]["subcategories"].items():
                            category_selected = st.checkbox(
                                f"{category} ({len(items)}개)", 
                                key=f"category_pc_linux_{category}"
                            )
                            
                            if category_selected:
                                category_items = {}
                                for item in items:
                                    item_selected = st.checkbox(
                                        item, 
                                        key=f"item_pc_linux_{item}", 
                                        value=True
                                    )
                                    category_items[item] = item_selected
                                selected_checks["PC-Linux"]["categories"][category] = category_items
            
            with col2:
                st.markdown("### 💾 데이터베이스 & 웹서비스")
                
                # MySQL
                mysql_all = st.checkbox("🐬 MySQL 보안 점검 (9개)", key="mysql_all")
                selected_checks["MySQL"] = {"all": mysql_all, "categories": {}}
                
                if mysql_all:
                    st.success("✅ MySQL 전체 9개 항목 선택됨")
                else:
                    with st.expander("📋 MySQL 세부 카테고리 선택"):
                        for category, items in vulnerability_categories["MySQL"]["subcategories"].items():
                            category_selected = st.checkbox(
                                f"{category} ({len(items)}개)", 
                                key=f"category_mysql_{category}"
                            )
                            
                            if category_selected:
                                category_items = {}
                                for item in items:
                                    item_selected = st.checkbox(
                                        item, 
                                        key=f"item_mysql_{item}", 
                                        value=True
                                    )
                                    category_items[item] = item_selected
                                selected_checks["MySQL"]["categories"][category] = category_items
                
                # Apache  
                apache_all = st.checkbox("🪶 Apache 보안 점검 (7개)", key="apache_all")
                selected_checks["Apache"] = {"all": apache_all, "categories": {}}
                
                if apache_all:
                    st.success("✅ Apache 전체 7개 항목 선택됨")
                else:
                    with st.expander("📋 Apache 세부 카테고리 선택"):
                        for category, items in vulnerability_categories["Apache"]["subcategories"].items():
                            category_selected = st.checkbox(
                                f"{category} ({len(items)}개)", 
                                key=f"category_apache_{category}"
                            )
                            
                            if category_selected:
                                category_items = {}
                                for item in items:
                                    item_selected = st.checkbox(
                                        item, 
                                        key=f"item_apache_{item}", 
                                        value=True
                                    )
                                    category_items[item] = item_selected
                                selected_checks["Apache"]["categories"][category] = category_items
                
                # Nginx
                nginx_all = st.checkbox("⚡ Nginx 보안 점검 (7개)", key="nginx_all")
                selected_checks["Nginx"] = {"all": nginx_all, "categories": {}}
                
                if nginx_all:
                    st.success("✅ Nginx 전체 7개 항목 선택됨")
                else:
                    with st.expander("📋 Nginx 세부 카테고리 선택"):
                        for category, items in vulnerability_categories["Nginx"]["subcategories"].items():
                            category_selected = st.checkbox(
                                f"{category} ({len(items)}개)", 
                                key=f"category_nginx_{category}"
                            )
                            
                            if category_selected:
                                category_items = {}
                                for item in items:
                                    item_selected = st.checkbox(
                                        item, 
                                        key=f"item_nginx_{item}", 
                                        value=True
                                    )
                                    category_items[item] = item_selected
                                selected_checks["Nginx"]["categories"][category] = category_items
                
                # PHP
                php_all = st.checkbox("🐘 PHP 보안 점검 (6개)", key="php_all")
                selected_checks["PHP"] = {"all": php_all, "categories": {}}
                
                if php_all:
                    st.success("✅ PHP 전체 6개 항목 선택됨")
                else:
                    with st.expander("📋 PHP 세부 카테고리 선택"):
                        for category, items in vulnerability_categories["PHP"]["subcategories"].items():
                            category_selected = st.checkbox(
                                f"{category} ({len(items)}개)", 
                                key=f"category_php_{category}"
                            )
                            
                            if category_selected:
                                category_items = {}
                                for item in items:
                                    item_selected = st.checkbox(
                                        item, 
                                        key=f"item_php_{item}", 
                                        value=True
                                    )
                                    category_items[item] = item_selected
                                selected_checks["PHP"]["categories"][category] = category_items
        else:
            # 🆕 서버별 개별 설정 UI
            st.markdown("### 🎯 서버별 개별 분석 설정")
            # 세션 상태에 서버별 선택 정보 저장
            if 'server_specific_checks' not in st.session_state:
                st.session_state.server_specific_checks = {}
            
            # 각 서버별로 탭 생성
            server_tabs = st.tabs([f"🖥️ {server}" for server in active_servers])
            
            for i, server_name in enumerate(active_servers):
                with server_tabs[i]:
                    st.markdown(f"#### {server_name} 서버 점검 설정")
                    
                    # 서버별 선택 상태 초기화
                    if server_name not in st.session_state.server_specific_checks:
                        st.session_state.server_specific_checks[server_name] = {}
                    
                    # 각 서버별로 독립적인 체크박스 생성
                    server_checks = render_server_analysis_options(
                        server_name, vulnerability_categories, i
                    )
                    st.session_state.server_specific_checks[server_name] = server_checks
                    
                    # 🔧 현재 선택 상태 표시
                    selected_count = 0
                    for service, selected in server_checks.items():
                        if isinstance(selected, dict) and selected.get("all", False):
                            selected_count += vulnerability_categories.get(service, {}).get("count", 0)
                        elif isinstance(selected, dict):
                            categories = selected.get("categories", {})
                            for items in categories.values():
                                if isinstance(items, dict):
                                    selected_count += sum(1 for item_selected in items.values() if item_selected)
                    
                    if selected_count > 0:
                        st.success(f"✅ 현재 {selected_count}개 점검 항목 선택됨")
                    else:
                        st.warning("⚠️ 아직 선택된 점검 항목이 없습니다")
            
            # 전체 선택된 항목 통합
            selected_checks = integrate_server_specific_checks(
                st.session_state.server_specific_checks, active_servers
            )

        # 선택 요약 표시
        st.markdown("---")

        if analysis_mode == "🔄 모든 서버 동일 설정":
            col_summary1, col_summary2, col_summary3 = st.columns(3)
            
            with col_summary1:
                total_selected = count_selected_checks(selected_checks, vulnerability_categories)
                st.metric("선택된 점검 항목", f"{total_selected}개", f"총 77개 중")
                
            with col_summary2:
                if total_selected > 0:
                    st.success(f"✅ {total_selected}개 점검 준비 완료")
                else:
                    st.warning("⚠️ 점검 항목을 선택해주세요")
        
            with col_summary3:
                estimated_seconds = len(active_servers) * total_selected * 8
                rounded_seconds = math.ceil(estimated_seconds / 10) * 10  # 10초 단위 반올림
                estimated_minutes = math.ceil(rounded_seconds / 60)  # 분 단위로 반올림
                st.info(f"⏱️ 예상 소요시간: {estimated_minutes}분")              
        else:
            # 🆕 서버별 요약 표시
            total_selected, server_breakdown = count_server_specific_checks(
                st.session_state.server_specific_checks, vulnerability_categories
            )
            
            col_summary1, col_summary2, col_summary3 = st.columns(3)
            
            with col_summary1:
                st.metric("전체 선택된 점검 항목", f"{total_selected}개", f"모든 서버 합계")
            
            with col_summary2:
                st.markdown("**서버별 점검 항목:**")
                for server_name, count in server_breakdown.items():
                    st.text(f"• {server_name}: {count}개")
            
            with col_summary3:
                if total_selected > 0:
                    st.success(f"✅ {total_selected}개 점검 준비 완료")
                    estimated_seconds = len(active_servers) * total_selected * 8
                    rounded_seconds = math.ceil(estimated_seconds / 10) * 10  # 10초 단위 반올림
                    estimated_minutes = math.ceil(rounded_seconds / 60)  # 분 단위로 반올림
                    st.info(f"⏱️ 예상 소요시간: {estimated_minutes}분")         
                else:
                    st.warning("⚠️ 점검 항목을 선택해주세요")

    # 취약점 점검은 활성화되었지만 서버가 선택되지 않은 경우
    elif not active_servers:
        st.info("📋 대상 서버를 선택하면 해당 서버의 취약점 점검 항목을 설정할 수 있습니다.")

    st.markdown("---")

    # 실행 버튼 및 상태
    st.header("🚀 Ansible 플레이북 실행")

    # 세션 상태 초기화
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

    if active_servers and vulnerability_categories:
        # 취약점 점검 시작 버튼
        if not st.session_state.playbook_generated:
            if st.button("🔍 취약점 점검 시작", type="primary", use_container_width=True):
                reset_playbook_session("새로운 취약점 점검 시작")
                # 플레이북 생성 및 저장
                with st.spinner("Ansible 플레이북 동적 생성 중..."):
                    # 타임스탬프로 결과 폴더 생성
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    result_folder_name = f"playbook_result_{timestamp}"
                    result_folder_path = os.path.join("playbooks", result_folder_name)
                    os.makedirs(result_folder_path, exist_ok=True)
                    os.makedirs(os.path.join(result_folder_path, "results"), exist_ok=True)  # 결과 하위 폴더도 미리 생성

                    if "서버별 개별 설정" in analysis_mode:  # ← 문자열 일부 매칭으로 변경
                        # 🔧 디버깅: 서버별 선택 상태 출력
                        print(f"🐛 서버별 개별 설정 모드 진입!")
                        print(f"🐛 analysis_mode: {analysis_mode}")
                        print(f"🐛 server_specific_checks: {st.session_state.get('server_specific_checks', {})}")
                        
                        playbook_tasks = generate_playbook_tasks(
                            {},  # 서버별 모드에서는 selected_checks 대신 server_specific_checks 사용
                            filename_mapping,
                            vulnerability_categories, 
                            analysis_mode="server_specific",  # ← 🔑 이 부분이 중요!
                            active_servers=active_servers,
                            server_specific_checks=st.session_state.get('server_specific_checks', {})
                        )
                        
                        st.session_state.analysis_mode = "server_specific"  # ← 🔑 올바른 모드 저장
                        st.session_state.server_task_details = generate_server_task_details(
                            st.session_state.get('server_specific_checks', {}), vulnerability_categories
                        )
                    else:
                        playbook_tasks = generate_playbook_tasks(
                            selected_checks, filename_mapping, vulnerability_categories,
                            analysis_mode="unified", active_servers=active_servers
                        )
                        st.session_state.analysis_mode = "unified"
                        st.session_state.server_task_details = None

                    # 🔧 디버깅: 생성된 태스크 수 확인
                    print(f"🐛 최종 analysis_mode: {st.session_state.get('analysis_mode', 'None')}")
                    print(f"🐛 생성된 playbook_tasks 수: {len(playbook_tasks)}")
                    print(f"🐛 playbook_tasks 내용: {playbook_tasks[:5] if playbook_tasks else '없음'}")

                    # 플레이북 파일로 저장할 때도 수정:
                    if "서버별 개별 설정" in analysis_mode:  # ← 문자열 매칭 수정
                        playbook_path, playbook_filename, timestamp = save_generated_playbook(
                            active_servers, 
                            playbook_tasks, 
                            result_folder_path,
                            analysis_mode="server_specific",  # ← 🔑 정확한 모드 전달
                            server_specific_checks=st.session_state.get('server_specific_checks', {}),
                            vulnerability_categories=vulnerability_categories,
                            filename_mapping=filename_mapping
                        )
                    else:
                        playbook_path, playbook_filename, timestamp = save_generated_playbook(
                            active_servers, 
                            playbook_tasks, 
                            result_folder_path,
                            analysis_mode="unified",
                            vulnerability_categories=vulnerability_categories,
                            filename_mapping=filename_mapping
                        )
                          
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
                    st.session_state.selected_checks = selected_checks if 'selected_checks' in locals() else {}
                    st.session_state.result_folder_path = result_folder_path
                    st.session_state.timestamp = timestamp  # 이 라인 추가
                    time.sleep(1)
                    
                    # 페이지 새로고침
                    st.rerun()
        
        # 플레이북이 생성된 후 실행 단계
        if st.session_state.playbook_generated:
            # 생성된 플레이북 정보 표시
            st.success("✅ 체크리스트들을 기반으로 인벤토리 & 플레이북 생성 및 저장 완료!")
            st.warning("⚠️ 이전에 생성된 플레이북이 보일 경우 하단의 🔄 새로운 점검 시작 버튼을 눌러주세요.")
            
            # 🔧 분석 모드에 따른 다른 처리
            if st.session_state.get('analysis_mode') == "⚙️ 서버별 개별 설정":
                # 서버별 개별 설정 모드
                total_checks = 0
                if st.session_state.get('server_task_details'):
                    total_checks = sum(details['count'] for details in st.session_state.server_task_details.values())
                
                # 기본 정보 (서버별 모드)
                playbook_info = {
                    "분석 모드": "서버별 개별 설정",
                    "대상 서버": active_servers,
                    "총 점검 항목": f"{total_checks}개 (모든 서버 합계)",
                    "서버별 점검 수": {server: details['count'] for server, details in st.session_state.get('server_task_details', {}).items()},
                    "생성된 플레이북": os.path.basename(st.session_state.playbook_path),
                    "저장 경로": st.session_state.playbook_path,
                    "inventory 파일": st.session_state.inventory_path,
                    "결과 저장 폴더": f"{st.session_state.result_folder_path}/results/",
                    "생성 시간": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "예상 소요 시간": f"{len(active_servers) * 2}분 (서버별 병렬 실행)"
                }
                
                # 기본 정보 표시
                st.json(playbook_info)
                
                # 🆕 서버별 상세 점검 항목 표시
                if st.session_state.get('server_task_details'):
                    st.subheader("📋 서버별 선택된 점검 항목 상세")
                    
                    for server_name, details in st.session_state.server_task_details.items():
                        with st.expander(f"🖥️ {server_name} ({details['count']}개 점검 항목)", expanded=True):
                            for service, tasks in details['services'].items():
                                if tasks:
                                    service_icons = {
                                        "Server-Linux": "🐧", "PC-Linux": "🖥️", 
                                        "MySQL": "🐬", "Apache": "🪶", 
                                        "Nginx": "⚡", "PHP": "🐘"
                                    }
                                    icon = service_icons.get(service, "📦")
                                    
                                    st.markdown(f"**{icon} {service} ({len(tasks)}개 항목)**")
                                    for i, task in enumerate(tasks, 1):
                                        st.markdown(f"&nbsp;&nbsp;&nbsp;&nbsp;{i}. {task}")
                                    st.markdown("")
                    
                    # 요약 정보
                    st.info(f"💡 총 {len(st.session_state.server_task_details)}개 서버에서 {total_checks}개 점검 항목이 선택되었습니다.")
                else:
                    st.warning("⚠️ 서버별 선택 정보를 찾을 수 없습니다.")
            
            else:
                # 통일 설정 모드 (기존 로직)
                total_checks = count_selected_checks(st.session_state.selected_checks, vulnerability_categories)
                
                # 서비스별로 선택된 항목들 정리
                selected_by_service = {}
                
                for service, selected in st.session_state.selected_checks.items():
                    if service in ["Server-Linux", "PC-Linux", "MySQL", "Apache", "Nginx", "PHP"] and isinstance(selected, dict):
                        service_tasks = []
                        
                        if selected.get("all", False):
                            # 전체 선택 시 모든 항목 추가
                            for category, items in vulnerability_categories[service]["subcategories"].items():
                                service_tasks.extend(items)
                        else:
                            # 개별 선택된 항목만 추가
                            categories = selected.get("categories", {})
                            for category, items in categories.items():
                                if isinstance(items, dict):
                                    for item, item_selected in items.items():
                                        if item_selected:
                                            service_tasks.append(item)
                        
                        if service_tasks:
                            selected_by_service[service] = service_tasks
                    
                    elif selected and service in vulnerability_categories:
                        # 단순 boolean 선택 방식
                        service_tasks = []
                        for category, items in vulnerability_categories[service]["subcategories"].items():
                            service_tasks.extend(items)
                        if service_tasks:
                            selected_by_service[service] = service_tasks
                
                # 기본 정보 (통일 모드)
                playbook_info = {
                    "분석 모드": "모든 서버 동일 설정",
                    "대상 서버": active_servers,
                    "총 점검 항목": f"{total_checks}개",
                    "점검 서비스": list(selected_by_service.keys()),
                    "생성된 플레이북": os.path.basename(st.session_state.playbook_path),
                    "저장 경로": st.session_state.playbook_path,
                    "inventory 파일": st.session_state.inventory_path,
                    "결과 저장 폴더": f"{st.session_state.result_folder_path}/results/",
                    "생성 시간": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                
                # 기본 정보 표시
                st.json(playbook_info)
                
                # 선택된 점검 항목을 서비스별로 상세 표시
                if selected_by_service:
                    st.subheader("📋 선택된 점검 항목 상세 목록")
                    
                    # 서비스별 탭 또는 expander로 표시
                    for service, tasks in selected_by_service.items():
                        service_icons = {
                            "Server-Linux": "🐧", "PC-Linux": "🖥️", 
                            "MySQL": "🐬", "Apache": "🪶",
                            "Nginx": "⚡", "PHP": "🐘"
                        }
                        
                        icon = service_icons.get(service, "📦")
                        
                        with st.expander(f"{icon} {service} ({len(tasks)}개 점검 항목)", expanded=True):
                            for i, task in enumerate(tasks, 1):
                                st.markdown(f"{i}. {task}")
                    
                    # 요약 정보
                    st.info(f"💡 총 {len(selected_by_service)}개 서비스에서 {total_checks}개 점검 항목이 선택되었습니다.")
                
                else:
                    st.warning("⚠️ 선택된 점검 항목이 없습니다.")
                    
            # 플레이북 경로 표시                        
            # 실행 경고 메시지
            st.warning("⚠️ 실제 서버에 변경 사항이 적용됩니다!")
            if st.button("▶️ 실행 시작 (생성된 Ansible 플레이북을 실제로 실행)", type="secondary", use_container_width=True):
                # 실행 명령어 표시
                st.subheader("🖥️ 실행 중인 Ansible 명령어")
                cmd_text = f"ansible-playbook -i {st.session_state.inventory_path} {st.session_state.playbook_path} --limit target_servers -v"
                st.code(cmd_text)
                
                # 실시간 출력 영역
                st.subheader("📄 실시간 실행 로그")
                output_container = st.empty()
                status_text = st.empty()
                
                # 실제 Ansible 실행
                try:
                    # 백엔드 콘솔에 실행 시작 알림
                    print(f"\n🔥 실제 실행 모드로 Ansible 플레이북 실행을 시작합니다...")
                    
                    output_queue, thread = execute_ansible_playbook(
                        st.session_state.playbook_path, 
                        st.session_state.inventory_path, 
                        active_servers,
                        st.session_state.result_folder_path,
                        st.session_state.timestamp  # 타임스탬프 추가
                    )
                    
                    # 로그 파일 정보 표시
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    log_filename = f"ansible_execute_log_{timestamp}.log"
                    st.info(f"📄 실행 로그가 다음 위치에 저장됩니다: `logs/{log_filename}`")
                    
                    displayed_logs = []
                    finished = False
                    # 초기값 추가
                    result_summary = {"성공한 태스크": 0, "변경된 설정": 0, "실패한 태스크": 0, "접근 불가 서버": 0}  # 초기값 추가
                    
                    while not finished:
                        try:
                            # 큐에서 출력 가져오기 (타임아웃 1초)
                            msg_type, content = output_queue.get(timeout=1)
                            
                            if msg_type == 'output':
                                # 빈 줄 필터링 및 공백 정리
                                if content and content.strip():
                                    cleaned_content = content.strip()
                                    displayed_logs.append(cleaned_content)
                                    
                                    # 스타일링된 로그 박스로 표시 (최근 100줄 유지)
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
                    
                    # 스레드 완료 대기
                    thread.join(timeout=5)
                    
                except Exception as e:
                    error_msg = f"실행 중 오류 발생: {str(e)}"
                    st.error(f"❌ {error_msg}")
                    print(f"❌ [STREAMLIT ERROR] {error_msg}")
                    result_summary = {"성공한 태스크": 0, "변경된 설정": 0, "실패한 태스크": 0, "접근 불가 서버": 0}
                    
                # 최종 실행 결과 요약
                st.subheader("📊 실행 결과 요약")
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    st.metric("✅ 성공", f"{result_summary['성공한 태스크']}개")
                with col2:
                    st.metric("🔄 변경", f"{result_summary['변경된 설정']}개")
                with col3:
                    st.metric("❌ 실패", f"{result_summary['실패한 태스크']}개")
                with col4:
                    st.metric("⚠️ 무시됨", f"{result_summary['무시된 태스크']}개")
                with col5:
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
    <p><strong>Askable</strong> | Ansible 기반 취약점 자동 점검 및 공격 탐지 시스템</p>
    <p>2025 현대오토에버 모빌리티 SW스쿨 IT보안 2기 @ Development Team 2</p>
    </div>
    """, unsafe_allow_html=True)

def generate_server_task_details(server_specific_checks, vulnerability_categories):
    """서버별 선택된 태스크 상세 정보 생성"""
    server_details = {}
    
    for server_name, server_checks in server_specific_checks.items():
        server_detail = {
            'count': 0,
            'services': {}
        }
        
        for service, selected in server_checks.items():
            if service in vulnerability_categories and isinstance(selected, dict):
                service_tasks = []
                
                if selected.get("all", False):
                    # 전체 선택 시 모든 항목 추가
                    for category, items in vulnerability_categories[service]["subcategories"].items():
                        service_tasks.extend(items)
                else:
                    # 개별 선택된 항목만 추가
                    categories = selected.get("categories", {})
                    for category, items in categories.items():
                        if isinstance(items, dict):
                            for item, item_selected in items.items():
                                if item_selected:
                                    service_tasks.append(item)
                
                if service_tasks:
                    server_detail['services'][service] = service_tasks
                    server_detail['count'] += len(service_tasks)
        
        server_details[server_name] = server_detail
    
    return server_details

# 🆕 추가 함수들
def render_server_analysis_options(server_name, vulnerability_categories, tab_index):
    """개별 서버의 분석 옵션 렌더링"""
    server_checks = {}
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("##### 🖥️ 운영체제")
        
        # Server-Linux (서버별 고유 키 사용)
        server_linux_all = st.checkbox(
            "🐧 Server-Linux 전체 (36개)", 
            key=f"server_linux_all_{server_name}_{tab_index}"
        )
        server_checks["Server-Linux"] = {"all": server_linux_all, "categories": {}}
        
        if server_linux_all:
            st.success("✅ Server-Linux 전체 36개 항목 선택됨")
        else:
            with st.expander("📋 Server-Linux 세부 카테고리 선택"):
                for category, items in vulnerability_categories["Server-Linux"]["subcategories"].items():
                    category_selected = st.checkbox(
                        f"{category} ({len(items)}개)", 
                        key=f"category_server_linux_{category}_{server_name}_{tab_index}"
                    )
                    
                    if category_selected:
                        category_items = {}
                        for item in items:
                            item_selected = st.checkbox(
                                item, 
                                key=f"item_server_linux_{item}_{server_name}_{tab_index}", 
                                value=True
                            )
                            category_items[item] = item_selected
                        server_checks["Server-Linux"]["categories"][category] = category_items
        
        st.markdown("---")
        
        # PC-Linux 완전 구현
        pc_linux_all = st.checkbox(
            "🖥️ PC-Linux 전체 (12개)", 
            key=f"pc_linux_all_{server_name}_{tab_index}"
        )
        server_checks["PC-Linux"] = {"all": pc_linux_all, "categories": {}}
        
        if pc_linux_all:
            st.success("✅ PC-Linux 전체 12개 항목 선택됨")
        else:
            with st.expander("📋 PC-Linux 세부 카테고리 선택"):
                for category, items in vulnerability_categories["PC-Linux"]["subcategories"].items():
                    category_selected = st.checkbox(
                        f"{category} ({len(items)}개)", 
                        key=f"category_pc_linux_{category}_{server_name}_{tab_index}"
                    )
                    
                    if category_selected:
                        category_items = {}
                        for item in items:
                            item_selected = st.checkbox(
                                item, 
                                key=f"item_pc_linux_{item}_{server_name}_{tab_index}", 
                                value=True
                            )
                            category_items[item] = item_selected
                        server_checks["PC-Linux"]["categories"][category] = category_items
    
    with col2:
        st.markdown("##### 💾 데이터베이스 & 웹서비스")
        
        # 모든 서비스들을 반복문으로 처리
        services = [
            ("MySQL", "🐬", 9),
            ("Apache", "🪶", 7),
            ("Nginx", "⚡", 7),
            ("PHP", "🐘", 6)
        ]
        
        for service_name, icon, count in services:
            service_all = st.checkbox(
                f"{icon} {service_name} 보안 점검 ({count}개)", 
                key=f"{service_name.lower()}_all_{server_name}_{tab_index}"
            )
            server_checks[service_name] = {"all": service_all, "categories": {}}
            
            if service_all:
                st.success(f"✅ {service_name} 전체 {count}개 항목 선택됨")
            else:
                with st.expander(f"📋 {service_name} 세부 카테고리 선택"):
                    for category, items in vulnerability_categories[service_name]["subcategories"].items():
                        category_selected = st.checkbox(
                            f"{category} ({len(items)}개)", 
                            key=f"category_{service_name.lower()}_{category}_{server_name}_{tab_index}"
                        )
                        
                        if category_selected:
                            category_items = {}
                            for item in items:
                                item_selected = st.checkbox(
                                    item, 
                                    key=f"item_{service_name.lower()}_{item}_{server_name}_{tab_index}", 
                                    value=True
                                )
                                category_items[item] = item_selected
                            server_checks[service_name]["categories"][category] = category_items
    
    return server_checks

def integrate_server_specific_checks(server_specific_checks, active_servers):
    """서버별 선택 사항을 통합하여 플레이북 생성용 형태로 변환"""
    integrated_checks = {}
    
    # 모든 서비스 타입 수집
    all_services = set()
    for server_checks in server_specific_checks.values():
        all_services.update(server_checks.keys())
    
    # 서비스별로 서버 매핑 생성
    for service in all_services:
        integrated_checks[service] = {
            "servers": {},  # 서버별 선택 상태
            "all": False,   # 전체 선택 여부 (사용 안함)
            "categories": {}
        }
        
        for server_name in active_servers:
            if server_name in server_specific_checks:
                server_service_check = server_specific_checks[server_name].get(service, {})
                integrated_checks[service]["servers"][server_name] = server_service_check
    
    return integrated_checks

def count_server_specific_checks(server_specific_checks, vulnerability_categories):
    """서버별 선택된 점검 항목 수 계산"""
    total_checks = 0
    server_breakdown = {}
    
    for server_name, server_checks in server_specific_checks.items():
        server_total = 0
        
        for service, selected in server_checks.items():
            if service in vulnerability_categories and isinstance(selected, dict):
                if selected.get("all", False):
                    server_total += vulnerability_categories[service]["count"]
                else:
                    categories = selected.get("categories", {})
                    for category, items in categories.items():
                        if isinstance(items, dict):
                            server_total += sum(1 for item_selected in items.values() if item_selected)
        
        server_breakdown[server_name] = server_total
        total_checks += server_total
    
    return total_checks, server_breakdown

# --- 메인 실행 로직 ---

# ✨ 세션 상태 키를 'role'로 변경하여 사용자 역할 관리
if "role" not in st.session_state:
    st.session_state.role = None

# ✨ 역할에 따라 다른 화면을 보여줌
if st.session_state.role == 'admin':
    render_main_app()
elif st.session_state.role == 'guest':
    render_guest_view()
else:
    # 로그인되지 않은 상태면 로그인 폼 표시
    render_login_form()