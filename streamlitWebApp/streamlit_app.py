import streamlit as st
import pandas as pd
import json
import time
import os
import queue
import glob
import re
from datetime import datetime, timedelta

from modules.history_manager import render_sidebar_with_history, show_analysis_report
from modules.inventory_handler import parse_inventory_file, save_inventory_file
from modules.playbook_manager import save_generated_playbook, execute_ansible_playbook, generate_task_filename, generate_playbook_tasks
from modules.input_utils import count_selected_checks, parse_play_recap

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

# 페이지 설정
st.set_page_config(
    page_title="Askable: Ansible 기반 취약점 자동 점검 시스템",
    page_icon="🔒",
    layout="wide"
)

# JSON 파일 로딩 함수
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

# 설정 파일들 로드
vulnerability_categories = load_json_config('vulnerability_categories.json')
filename_mapping = load_json_config('filename_mapping.json')
            
# 사이드바 설정
render_sidebar_with_history(vulnerability_categories, filename_mapping)

# 쿼리 파라미터 확인해서 분석 리포트 페이지 표시할지 결정
query_params = st.query_params
selected_report = query_params.get("report", None)
selected_page = query_params.get("page", None)

# 포트 스캐닝 페이지 라우팅
if selected_page == "port_scanning":
    try:
        import dynamic_analysis
        dynamic_analysis.main()
        st.stop()
    except ImportError:
        st.error("❌ dynamic_analysis.py 모듈을 찾을 수 없습니다.")
        if st.button("⬅️ 메인으로 돌아가기"):
            st.query_params.clear()
            st.rerun()
        st.stop()

# 웹 애플리케이션 테스트 페이지 라우팅
if selected_page == "web_app_test":
    try:
        import web_app_test
        web_app_test.main()
        st.stop()
    except ImportError:
        st.error("❌ web_app_test.py 모듈을 찾을 수 없습니다.")
        if st.button("⬅️ 메인으로 돌아가기"):
            st.query_params.clear()
            st.rerun()
        st.stop()

if selected_report:
    # 분석 리포트 페이지 표시
    show_analysis_report(selected_report)
    st.stop()  # 메인 페이지 렌더링 중단
    
# 메인 타이틀
st.title("Askable: ansible 기반 서버 취약점 자동 점검 시스템")

col1, col2 = st.columns(2)

with col1:
    if st.button("🌐 포트 스캐닝 (Dynamic Analysis)", use_container_width=True, key="btn_back_from_dynamic"):
        st.query_params.update({"page": "port_scanning"})
        st.rerun()

with col2:
    if st.button("🕷️ 웹 애플리케이션 테스트", use_container_width=True, key="btn_back_from_webApp"):
        st.query_params.update({"page": "web_app_test"})
        st.rerun()
        
# 취약점 점검 체계 선택
st.header("🔍 정적 분석 (Static Analysis)")

# 시스템 구성 요소 표시
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

# inventory.ini 파일 업로드 섹션
st.subheader("🖥️ Managed Nodes 구성 (Inventory 파일 업로드)")

# 파일 업로드 위젯
uploaded_file = st.file_uploader(
    "Ansible inventory.ini 파일을 업로드하세요",
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
    st.warning("📂 inventory.ini 파일을 업로드해주세요.")

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

# 정적 분석 세부 설정 - 서버 선택 시에만 표시
if active_servers and vulnerability_categories:
    st.subheader("📝 정적 분석 - 취약점 점검 항목 선택")
    
    # 서비스별 점검 항목 선택
    selected_checks = {}
    
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
    
    # 선택 요약 표시
    st.markdown("---")
    
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
        estimated_time = len(active_servers) * (total_selected // 10) if total_selected > 0 else 0
        st.info(f"⏱️ 예상 소요시간: {estimated_time}분")
                    
# 정적 분석은 활성화되었지만 서버가 선택되지 않은 경우
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
            # 플레이북 생성 및 저장
            with st.spinner("Ansible 플레이북 동적 생성 중..."):
                # 타임스탬프로 결과 폴더 생성
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                result_folder_name = f"playbook_result_{timestamp}"
                result_folder_path = os.path.join("playbooks", result_folder_name)
                os.makedirs(result_folder_path, exist_ok=True)
                os.makedirs(os.path.join(result_folder_path, "results"), exist_ok=True)  # 결과 하위 폴더도 미리 생성
                
                # 선택된 점검 항목에 따른 플레이북 태스크 생성
                playbook_tasks = generate_playbook_tasks(selected_checks, filename_mapping, vulnerability_categories) if 'selected_checks' in locals() else []
                
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
                
                # 플레이북 파일로 저장 (개선된 방식)
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
                st.session_state.selected_checks = selected_checks if 'selected_checks' in locals() else {}
                st.session_state.result_folder_path = result_folder_path
                st.session_state.timestamp = timestamp  # 이 라인 추가
                time.sleep(1)
                
                # 페이지 새로고침
                st.rerun()
    
    # 플레이북이 생성된 후 실행 단계
    if st.session_state.playbook_generated:
        # 생성된 플레이북 정보 표시
        st.success("✅ 플레이북 생성 및 저장 완료!")
        
        # 선택된 점검 항목 카운트 및 서비스별 상세 목록 생성
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
        
        # 기본 정보
        playbook_info = {
            "대상 서버": active_servers,
            "총 점검 항목": f"{total_checks}개",
            "점검 서비스": list(selected_by_service.keys()),
            "생성된 플레이북": os.path.basename(st.session_state.playbook_path),
            "저장 경로": st.session_state.playbook_path,
            "inventory 파일": st.session_state.inventory_path,
            "결과 저장 폴더": f"{st.session_state.result_folder_path}/results/",
            "생성 시간": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "예상 소요 시간": f"{len(active_servers) * 3}분"
        }
        
        # 기본 정보 표시
        st.json(playbook_info)
        
        # 선택된 점검 항목을 서비스별로 상세 표시
        if selected_by_service:
            st.subheader("📋 선택된 점검 항목 상세 목록")
            
            # 서비스별 탭 또는 expander로 표시
            for service, tasks in selected_by_service.items():
                service_icons = {
                    "Server-Linux": "🐧",
                    "PC-Linux": "🖥️", 
                    "MySQL": "🐬",
                    "Apache": "🪶",
                    "Nginx": "⚡",
                    "PHP": "🐘"
                }
                
                icon = service_icons.get(service, "📦")
                
                with st.expander(f"{icon} {service} ({len(tasks)}개 점검 항목)", expanded=True):
                    for i, task in enumerate(tasks, 1):
                        st.markdown(f"{i}. {task}")
            
            # 요약 정보
            st.info(f"💡 총 {len(selected_by_service)}개 서비스에서 {total_checks}개 점검 항목이 선택되었습니다.")
        
        else:
            st.warning("⚠️ 선택된 점검 항목이 없습니다.")
                    
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
<p><strong>Team 2</strong> | Ansible 기반 서버 취약점 자동 점검 및 보고서 생성 시스템</p>
<p>KISA 한국인터넷진흥원 2024.06 클라우드 취약점 점검 가이드 기반</p>
</div>
""", unsafe_allow_html=True)