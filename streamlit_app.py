import streamlit as st
import pandas as pd
import json
import time
import os
import queue
from datetime import datetime

from modules.inventory_handler import parse_inventory_file, save_inventory_file
from modules.playbook_manager import save_generated_playbook, execute_ansible_playbook, generate_task_filename, generate_playbook_tasks
from modules.input_utils import count_selected_checks

# 페이지 설정
st.set_page_config(
    page_title="Ansible 기반 서버 취약점 자동 점검 시스템",
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
st.sidebar.title("🔧 Control Node")
st.sidebar.markdown("**Ansible 플레이북 제어**")

# 설정 파일 상태 표시
if vulnerability_categories and filename_mapping:
    st.sidebar.success("✅ 설정 파일 로드 완료")
else:
    st.sidebar.error("❌ 설정 파일 로드 실패")
    st.sidebar.text("필요한 파일:")
    st.sidebar.text("- vulnerability_categories.json")
    st.sidebar.text("- filename_mapping.json")

# 메인 타이틀
st.title("🔒 Ansible 기반 서버 취약점 자동 점검 시스템")

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

# Managed Nodes 선택 섹션
st.header("🖥️ Managed Nodes 구성")

# inventory.ini 파일 업로드 섹션
st.subheader("📂 Inventory 파일 업로드")

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

# 취약점 점검 체계 선택
st.header("🔍 취약점 점검 체계")

# 분석 방법 선택 (정적 분석만 활성화)
st.subheader("분석 종류 선택")
col1, col2, col3 = st.columns(3)

with col1:
    static_enabled = st.checkbox("정적 분석 (Static Analysis)", help="**기준 가이드라인**: KISA 한국인터넷진흥원 2024.06 클라우드 취약점 점검 가이드")

with col2:
    st.checkbox("동적 분석 (Dynamic Analysis)", disabled=True, help="개발 중 - 추후 지원 예정")

with col3:
    st.checkbox("네트워크 분석 (Network Analysis)", disabled=True, help="개발 중 - 추후 지원 예정")

# 정적 분석 세부 설정 - 서버 선택 시에만 표시
if static_enabled and active_servers and vulnerability_categories:
    st.subheader("📝 정적 분석 - 취약점 점검 항목 선택")
    
    # 활성 서버에서 사용 가능한 서비스 추출
    available_services = set()
    for server_name in active_servers:
        if server_name in servers_info:
            available_services.update(servers_info[server_name]["services"])
    
    if not available_services:
        st.warning("⚠️ 선택된 서버에 점검 가능한 서비스가 없습니다.")
    else:
        # 서비스별 점검 항목 선택
        selected_checks = {}
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🖥️ 운영체제 관련**")
            
            if "Server-Linux" in available_services:
                server_linux_all = st.checkbox("Server-Linux 전체 (36개)", key="server_linux_all")
                
                st.markdown("**세부 카테고리 선택:**")
                selected_checks["Server-Linux"] = {"all": server_linux_all, "categories": {}}
                
                for category, items in vulnerability_categories["Server-Linux"]["subcategories"].items():
                    # 전체 선택 시 모든 카테고리 자동 선택
                    category_selected = st.checkbox(
                        f"{category} ({len(items)}개)", 
                        key=f"category_{category}",
                        value=server_linux_all,
                        disabled=server_linux_all
                    )
                    
                    if category_selected or server_linux_all:
                        with st.expander(f"{category} 세부 항목", expanded=server_linux_all):
                            category_items = {}
                            for item in items:
                                # 전체 선택 시 모든 세부 항목도 자동 선택
                                item_selected = st.checkbox(
                                    item, 
                                    key=f"item_{item}", 
                                    value=True if (server_linux_all or category_selected) else False,
                                    disabled=server_linux_all
                                )
                                category_items[item] = item_selected
                            selected_checks["Server-Linux"]["categories"][category] = category_items
            
            if "PC-Linux" in available_services:
                pc_linux_selected = st.checkbox("PC-Linux 전체 (12개)", key="pc_linux_all")
                selected_checks["PC-Linux"] = pc_linux_selected
        
        with col2:
            st.markdown("**💾 데이터베이스 & 웹서비스**")
            
            if "MySQL" in available_services:
                mysql_selected = st.checkbox("MySQL 보안 점검 (9개)", key="mysql_all")
                selected_checks["MySQL"] = mysql_selected
                
            if "Apache" in available_services:
                apache_selected = st.checkbox("Apache 보안 점검 (7개)", key="apache_all") 
                selected_checks["Apache"] = apache_selected
                
            if "Nginx" in available_services:
                nginx_selected = st.checkbox("Nginx 보안 점검 (7개)", key="nginx_all")
                selected_checks["Nginx"] = nginx_selected
                
            if "PHP" in available_services:
                php_selected = st.checkbox("PHP 보안 점검 (6개)", key="php_all")
                selected_checks["PHP"] = php_selected
                
            if "SQLite" in available_services:
                sqlite_selected = st.checkbox("SQLite 보안 점검 (6개)", key="sqlite_all")
                selected_checks["SQLite"] = sqlite_selected
            
            if "WebApp" in available_services:
                webapp_selected = st.checkbox("WebApp 보안 점검", key="webapp_all")
                selected_checks["WebApp"] = webapp_selected

# 정적 분석은 활성화되었지만 서버가 선택되지 않은 경우
elif static_enabled and not active_servers:
    st.markdown("---")
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

if active_servers and static_enabled and vulnerability_categories:
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
                playbook_tasks = generate_playbook_tasks(selected_checks, filename_mapping) if 'selected_checks' in locals() else []
                
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
                playbook_path, playbook_filename = save_generated_playbook(active_servers, playbook_tasks, result_folder_path)
                
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
                
                time.sleep(1)
                
                # 페이지 새로고침
                st.rerun()
    
    # 플레이북이 생성된 후 실행 단계
    if st.session_state.playbook_generated:
        # 생성된 플레이북 정보 표시
        st.success("✅ 플레이북 생성 및 저장 완료!")
        
        # 선택된 점검 항목 카운트
        total_checks = count_selected_checks(st.session_state.selected_checks, vulnerability_categories)
        
        playbook_info = {
            "대상 서버": active_servers,
            "총 점검 항목": f"{total_checks}개",
            "점검 서비스": list(st.session_state.selected_checks.keys()),
            "생성된 플레이북": os.path.basename(st.session_state.playbook_path),
            "저장 경로": st.session_state.playbook_path,
            "inventory 파일": st.session_state.inventory_path,
            "결과 저장 폴더": f"{st.session_state.result_folder_path}/results/",
            "생성 시간": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "예상 소요 시간": f"{len(active_servers) * 3}분"
        }
        
        st.json(playbook_info)
        
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
                    st.session_state.result_folder_path
                )
                
                # 로그 파일 정보 표시
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                log_filename = f"ansible_execute_log_{timestamp}.log"
                st.info(f"📄 실행 로그가 다음 위치에 저장됩니다: `logs/{log_filename}`")
                
                displayed_logs = []
                finished = False
                
                while not finished:
                    try:
                        # 큐에서 출력 가져오기 (타임아웃 1초)
                        msg_type, content = output_queue.get(timeout=1)
                        
                        if msg_type == 'output':
                            displayed_logs.append(content)
                            # 스타일링된 로그 박스로 표시 (최근 100줄 유지)
                            log_text = '\n'.join(displayed_logs[-100:])
                            
                            # code 위젯을 사용하되 스크롤을 강제하기 위해 마지막에 공백 라인 추가
                            display_text = log_text + '\n' + '─' * 50 + f' (실시간 업데이트 {len(displayed_logs)}) ' + '─' * 50
                            
                            output_container.code(display_text, language='bash')
                            
                        elif msg_type == 'finished':
                            finished = True
                            if content == 0:
                                st.success("🎉 Ansible 플레이북 실행 완료!")
                                st.success(f"📄 전체 실행 로그가 `logs/{log_filename}`에 저장되었습니다.")
                                st.success(f"📁 점검 결과 파일들이 `{st.session_state.result_folder_path}/results/`에 저장되었습니다.")
                                print("🎉 스트림릿 UI에서도 실행 완료 확인됨")
                            else:
                                st.error(f"❌ 실행 실패 (종료 코드: {content})")
                                print(f"❌ 스트림릿 UI에서도 실행 실패 확인됨 (코드: {content})")
                                
                        elif msg_type == 'error':
                            st.error(f"❌ 실행 오류: {content}")
                            print(f"❌ 스트림릿 UI에서도 오류 확인됨: {content}")
                            finished = True
                            
                    except queue.Empty:
                        continue
                
                # 스레드 완료 대기
                thread.join(timeout=5)
                
            except Exception as e:
                error_msg = f"실행 중 오류 발생: {str(e)}"
                st.error(f"❌ {error_msg}")
                print(f"❌ [STREAMLIT ERROR] {error_msg}")
            
            # 최종 실행 결과 요약
            st.subheader("📊 실행 결과 요약")
            result_summary = {
                "성공한 태스크": "0개",
                "변경된 설정": "0개", 
                "실패한 태스크": "0개",
                "접근 불가 서버": "0개"
            }
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("✅ 성공", result_summary["성공한 태스크"])
            with col2:
                st.metric("🔄 변경", result_summary["변경된 설정"])
            with col3:
                st.metric("❌ 실패", result_summary["실패한 태스크"])
            with col4:
                st.metric("🚫 접근불가", result_summary["접근 불가 서버"])
        
        
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