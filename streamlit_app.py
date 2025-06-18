import streamlit as st
import pandas as pd
import json
import yaml
from datetime import datetime
import time
import os
import subprocess
import threading
import queue

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

def save_generated_playbook(active_servers, playbook_tasks):
    """생성된 플레이북을 파일로 저장"""
    
    # 메인 플레이북 구조 생성 (import_playbook 방식)
    playbook_content = []
    
    # 첫 번째 플레이: 기본 설정
    main_play = {
        'name': 'KISA Security Vulnerability Check',
        'hosts': 'target_servers',
        'become': True
    }
    playbook_content.append(main_play)
    
    # import_playbook들 추가
    for task in playbook_tasks:
        task_name = task.replace('    - import_tasks: ', '')
        import_entry = {
            'import_playbook': "../tasks/" + task_name
        }
        playbook_content.append(import_entry)
    
    # 파일명 생성 (타임스탬프 포함)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_check_{timestamp}.yml"
    filepath = os.path.join("playbooks", filename)
    
    # 디렉터리 생성
    os.makedirs("playbooks", exist_ok=True)
    
    # 결과 저장용 폴더 생성
    result_folder_name = f"playbook_result_{timestamp}"
    result_folder_path = os.path.join("playbooks", result_folder_name)
    os.makedirs(result_folder_path, exist_ok=True)
    
    # YAML 파일로 저장
    with open(filepath, 'w', encoding='utf-8') as f:
        yaml.dump(playbook_content, f, default_flow_style=False, allow_unicode=True)
    
    return filepath, filename, result_folder_path

def execute_ansible_playbook(playbook_path, inventory_path, limit_hosts):
    """백엔드에서 Ansible 플레이북 실행"""
    
    # 로그 파일 경로 생성
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"ansible_execute_log_{timestamp}.log"
    log_path = os.path.join("logs", log_filename)
    
    # logs 디렉터리 생성
    os.makedirs("logs", exist_ok=True)
    
    # 실행 명령어 구성
    cmd = [
        'ansible-playbook',
        '-i', inventory_path,
        playbook_path,
        '--limit', ','.join(limit_hosts),
        '-v'
    ]
    
    # 백엔드 콘솔에 명령어 출력
    print(f"\n{'='*80}")
    print(f"🚀 ANSIBLE PLAYBOOK 실행 시작")
    print(f"{'='*80}")
    print(f"📝 명령어: {' '.join(cmd)}")
    print(f"📂 플레이북: {playbook_path}")
    print(f"📋 인벤토리: {inventory_path}")
    print(f"🎯 대상 서버: {', '.join(limit_hosts)}")
    print(f"📄 로그 파일: {log_path}")
    print(f"{'='*80}\n")
    
    # 실행 결과를 담을 큐
    output_queue = queue.Queue()
    
    def run_command():
        log_lines = []  # 로그 파일에 저장할 내용
        
        try:
            # 로그 파일 헤더 작성
            log_header = [
                f"=== Ansible Playbook 실행 로그 ===",
                f"실행 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"명령어: {' '.join(cmd)}",
                f"플레이북: {playbook_path}",
                f"인벤토리: {inventory_path}",
                f"대상 서버: {', '.join(limit_hosts)}",
                f"{'='*50}",
                ""
            ]
            log_lines.extend(log_header)
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # 실시간 출력 수집 및 백엔드 콘솔 출력
            for line in process.stdout:
                line_stripped = line.strip()
                
                # 백엔드 콘솔에 실시간 출력
                print(f"[ANSIBLE] {line_stripped}")
                
                # 로그 파일용 라인 추가
                log_lines.append(f"[{datetime.now().strftime('%H:%M:%S')}] {line_stripped}")
                
                # 스트림릿용 큐에도 추가
                output_queue.put(('output', line_stripped))
            
            # 프로세스 완료 대기
            return_code = process.wait()
            
            # 완료 메시지를 로그에 추가
            completion_msg = f"실행 완료 - 종료 코드: {return_code}"
            log_lines.append(f"\n{'='*50}")
            log_lines.append(f"[{datetime.now().strftime('%H:%M:%S')}] {completion_msg}")
            log_lines.append(f"실행 종료 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # 로그 파일에 저장
            try:
                with open(log_path, 'w', encoding='utf-8') as log_file:
                    log_file.write('\n'.join(log_lines))
                print(f"📄 로그 저장 완료: {log_path}")
            except Exception as log_error:
                print(f"❌ 로그 파일 저장 실패: {str(log_error)}")
            
            # 백엔드 콘솔에 완료 메시지
            print(f"\n{'='*80}")
            if return_code == 0:
                print(f"✅ ANSIBLE PLAYBOOK 실행 완료 (종료 코드: {return_code})")
            else:
                print(f"❌ ANSIBLE PLAYBOOK 실행 실패 (종료 코드: {return_code})")
            print(f"{'='*80}\n")
            
            output_queue.put(('finished', return_code))
            
        except Exception as e:
            error_msg = f"실행 오류: {str(e)}"
            log_lines.append(f"\n[{datetime.now().strftime('%H:%M:%S')}] ERROR: {error_msg}")
            
            # 에러 발생 시에도 로그 파일 저장
            try:
                with open(log_path, 'w', encoding='utf-8') as log_file:
                    log_file.write('\n'.join(log_lines))
                print(f"📄 에러 로그 저장 완료: {log_path}")
            except Exception as log_error:
                print(f"❌ 에러 로그 파일 저장 실패: {str(log_error)}")
            
            print(f"❌ [ERROR] {error_msg}")
            output_queue.put(('error', error_msg))
    
    # 백그라운드에서 실행
    thread = threading.Thread(target=run_command)
    thread.daemon = True
    thread.start()
    
    return output_queue, thread

def save_inventory_file(servers_info, selected_servers=None):
    """서버 정보를 inventory 파일로 저장 (선택된 서버들을 target_servers 그룹으로 설정)"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    inventory_filename = f"inventory_{timestamp}.ini"
    inventory_path = os.path.join("inventories", inventory_filename)
    
    # 디렉터리 생성
    os.makedirs("inventories", exist_ok=True)
    
    print(f"\n=== INVENTORY 파일 생성 ===")
    print(f"파일 경로: {inventory_path}")
    print(f"선택된 서버들: {selected_servers}")
    
    inventory_content = []
    groups = {}
    
    # 선택된 서버들만 필터링 (선택된 서버가 있을 때만)
    if selected_servers:
        filtered_servers_info = {name: info for name, info in servers_info.items() if name in selected_servers}
        print(f"필터링된 서버들: {list(filtered_servers_info.keys())}")
    else:
        filtered_servers_info = servers_info
        print(f"모든 서버 사용: {list(servers_info.keys())}")
    
    # 그룹별로 서버 정리
    for server_name, info in filtered_servers_info.items():
        group = info.get('group', 'default')
        if group not in groups:
            groups[group] = []
        groups[group].append((server_name, info))
    
    # 실제 [all:vars]에 있던 변수들만 구분 (전역 변수)
    true_global_vars = {}
    server_specific_vars = set()
    
    # 먼저 각 서버별로 정의된 변수들을 수집
    for server_name, info in filtered_servers_info.items():
        ansible_vars = info.get('ansible_vars', {})
        for var_name in ansible_vars.keys():
            # 개별 서버에서 정의된 변수들은 server_specific으로 간주
            if var_name in ['ansible_host', 'ansible_port', 'ansible_user', 'ansible_connection', 'ansible_become_pass']:
                server_specific_vars.add(var_name)
    
    # 진짜 전역 변수는 개별 서버에 정의되지 않은 것들만
    for server_name, info in filtered_servers_info.items():
        ansible_vars = info.get('ansible_vars', {})
        for var_name, var_value in ansible_vars.items():
            if var_name not in server_specific_vars:
                # 모든 서버에 동일한 값으로 존재하는지 확인
                is_truly_global = True
                for other_server, other_info in filtered_servers_info.items():
                    other_vars = other_info.get('ansible_vars', {})
                    if var_name not in other_vars or other_vars[var_name] != var_value:
                        is_truly_global = False
                        break
                
                if is_truly_global:
                    true_global_vars[var_name] = var_value
    
    # 1. target_servers 그룹 생성 (선택된 모든 서버 포함) - 플레이북 실행용
    if filtered_servers_info:
        inventory_content.append("[target_servers]")
        print(f"\n[target_servers] 그룹 생성:")
        
        for server_name, info in filtered_servers_info.items():
            line = server_name
            
            # 개별 변수들 추가 (전역 변수가 아닌 것들)
            ansible_vars = info.get('ansible_vars', {})
            individual_vars = []
            
            for var_name, var_value in ansible_vars.items():
                # 전역 변수가 아닌 것들만 개별 서버 라인에 추가
                if var_name not in true_global_vars:
                    individual_vars.append(f"{var_name}={var_value}")
            
            if individual_vars:
                line += " " + " ".join(individual_vars)
            
            inventory_content.append(line)
            print(f"  {line}")
        
        inventory_content.append("")  # 그룹 간 빈 줄
    
    # 2. 기존 그룹별 호스트 섹션 생성 (원본 형태 유지) - 참조용
    for group_name, servers in groups.items():
        inventory_content.append(f"[{group_name}]")
        print(f"\n[{group_name}] 그룹:")
        
        for server_name, info in servers:
            line = server_name
            
            # 개별 변수들 추가 (전역 변수가 아닌 것들)
            ansible_vars = info.get('ansible_vars', {})
            individual_vars = []
            
            for var_name, var_value in ansible_vars.items():
                # 전역 변수가 아닌 것들만 개별 서버 라인에 추가
                if var_name not in true_global_vars:
                    individual_vars.append(f"{var_name}={var_value}")
            
            if individual_vars:
                line += " " + " ".join(individual_vars)
            
            inventory_content.append(line)
            print(f"  {line}")
        
        inventory_content.append("")  # 그룹 간 빈 줄
    
    # [all:vars] 섹션 추가 (진짜 전역 변수만)
    if true_global_vars:
        inventory_content.append("[all:vars]")
        print(f"\n[all:vars] 섹션:")
        for var_name, var_value in true_global_vars.items():
            var_line = f"{var_name}={var_value}"
            inventory_content.append(var_line)
            print(f"  {var_line}")
    
    # 파일로 저장
    final_content = '\n'.join(inventory_content)
    print(f"\n=== 최종 inventory 내용 ===")
    print(final_content)
    
    with open(inventory_path, 'w', encoding='utf-8') as f:
        f.write(final_content)
    
    print(f"\n파일 저장 완료: {inventory_path}")
    return inventory_path

# 설정 파일들 로드
vulnerability_categories = load_json_config('vulnerability_categories.json')
filename_mapping = load_json_config('filename_mapping.json')

def parse_inventory_file(file_content):
    """inventory.ini 파일을 파싱하여 서버 정보 추출"""
    servers = {}
    current_group = None
    global_vars = {}
    is_vars_section = False
    
    lines = file_content.decode('utf-8').strip().split('\n')
    
    print("=== INVENTORY 파싱 시작 ===")
    
    for line_num, line in enumerate(lines, 1):
        original_line = line
        line = line.strip()
        
        print(f"Line {line_num}: '{original_line}' -> 처리: '{line}'")
        
        # 빈 줄이나 주석은 건너뛰기
        if not line or line.startswith('#'):
            print(f"  -> 빈 줄 또는 주석으로 건너뛰기")
            continue
            
        # 그룹 섹션 [webservers], [databases], [all:vars] 등
        if line.startswith('[') and line.endswith(']'):
            section_name = line[1:-1]
            print(f"  -> 섹션 발견: '{section_name}'")
            
            if section_name == 'all:vars':
                is_vars_section = True
                current_group = None
                print(f"  -> [all:vars] 섹션 시작")
            elif ':vars' in section_name:
                is_vars_section = True
                current_group = None
                print(f"  -> 변수 섹션: {section_name}")
            elif ':children' in section_name:
                is_vars_section = False
                current_group = None
                print(f"  -> children 섹션: {section_name} (건너뛰기)")
            else:
                is_vars_section = False
                current_group = section_name
                print(f"  -> 호스트 그룹 섹션: '{current_group}'")
            continue
            
        # [all:vars] 또는 다른 vars 섹션에서 전역 변수 처리
        if is_vars_section:
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                global_vars[key] = value
                print(f"  -> 전역 변수 추가: {key} = {value}")
            else:
                print(f"  -> vars 섹션에서 = 없는 라인 무시: '{line}'")
            continue
            
        # 호스트 그룹이 설정되지 않았으면 건너뛰기
        if not current_group:
            print(f"  -> 그룹이 없어서 건너뛰기: '{line}'")
            continue
            
        # 서버 정의 라인 파싱
        parts = line.split()
        if not parts:
            print(f"  -> 빈 parts로 건너뛰기")
            continue
            
        server_name = parts[0]
        print(f"  -> 서버 이름: '{server_name}', 그룹: '{current_group}'")
        
        # ansible_ 변수로 시작하는 건 서버가 아니므로 건너뛰기
        if server_name.startswith('ansible_'):
            print(f"  -> ansible_ 변수라서 건너뛰기: '{server_name}'")
            continue
        
        # 서버 정보 초기화
        server_info = {
            "ip": "Unknown",
            "description": f"{current_group} 그룹 서버",
            "services": ["Server-Linux"],
            "group": current_group,
            "ansible_vars": {}
        }
        
        # 서버 라인에 있는 개별 변수들 파싱
        for part in parts[1:]:
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'ansible_host':
                    server_info["ip"] = value
                    server_info["ansible_vars"][key] = value  # ansible_host도 변수로 보존
                elif key == 'services':
                    services = [s.strip().title() for s in value.split(',')]
                    server_info["services"] = services
                elif key == 'description':
                    server_info["description"] = value.replace('_', ' ')
                else:
                    server_info["ansible_vars"][key] = value
                
                print(f"    -> 개별 변수: {key} = {value}")
        
        servers[server_name] = server_info
        print(f"  -> 서버 '{server_name}' 추가 완료")
    
    print(f"\n=== 전역 변수 적용 ===")
    print(f"전역 변수들: {global_vars}")
    
    # 전역 변수를 모든 서버에 적용 (개별 설정이 우선)
    for server_name, server_info in servers.items():
        print(f"\n서버 '{server_name}'에 전역 변수 적용:")
        for var_name, var_value in global_vars.items():
            if var_name not in server_info["ansible_vars"]:
                server_info["ansible_vars"][var_name] = var_value
                print(f"  -> 추가: {var_name} = {var_value}")
            else:
                print(f"  -> 개별 설정 우선: {var_name} (기존값 유지)")
        
        # ansible_host가 설정되었다면 IP 업데이트
        if 'ansible_host' in server_info["ansible_vars"] and server_info["ip"] == "Unknown":
            server_info["ip"] = server_info["ansible_vars"]['ansible_host']
            print(f"  -> IP 업데이트: {server_info['ip']}")
    
    print(f"\n=== 최종 결과 ===")
    for server_name, server_info in servers.items():
        print(f"서버: {server_name}")
        print(f"  IP: {server_info['ip']}")
        print(f"  그룹: {server_info['group']}")
        print(f"  변수: {server_info['ansible_vars']}")
    
    return servers

def generate_task_filename(item_description):
    """KISA 점검 항목 설명을 파일명으로 변환"""
    item_code = item_description.split(":")[0].strip()
    return filename_mapping.get(item_code, f"{item_code}_security_check.yml")

def generate_playbook_tasks(selected_checks):
    """선택된 점검 항목에 따라 플레이북 태스크 생성"""
    playbook_tasks = []
    
    for service, selected in selected_checks.items():
        if service == "Server-Linux" and isinstance(selected, dict):
            if selected["all"]:
                # 전체 선택 시 모든 항목 포함
                for category, items in vulnerability_categories["Server-Linux"]["subcategories"].items():
                    for item in items:
                        task_file = generate_task_filename(item)
                        playbook_tasks.append(task_file)
            else:
                # 개별 선택된 항목만 포함
                for category, items in selected["categories"].items():
                    if isinstance(items, dict):
                        for item, item_selected in items.items():
                            if item_selected:
                                task_file = generate_task_filename(item)
                                playbook_tasks.append(task_file)
        elif selected and service != "Server-Linux":
            # 다른 서비스들
            playbook_tasks.append(f"{service.lower()}_security_check.yml")
    
    return playbook_tasks

def count_selected_checks(selected_checks):
    """선택된 점검 항목 수 계산"""
    total_checks = 0
    
    for service, selected in selected_checks.items():
        if service == "Server-Linux" and isinstance(selected, dict):
            if selected["all"]:
                total_checks += vulnerability_categories["Server-Linux"]["count"]
            else:
                for category, items in selected["categories"].items():
                    if isinstance(items, dict):
                        total_checks += sum(1 for item_selected in items.values() if item_selected)
        elif selected and service in vulnerability_categories:
            total_checks += vulnerability_categories[service]["count"]
    
    return total_checks

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

if active_servers and static_enabled and vulnerability_categories:
    # 취약점 점검 시작 버튼
    if not st.session_state.playbook_generated:
        if st.button("🔍 취약점 점검 시작", type="primary", use_container_width=True):
            # 플레이북 생성 및 저장
            with st.spinner("Ansible 플레이북 동적 생성 중..."):
                # 선택된 점검 항목에 따른 플레이북 태스크 생성
                playbook_tasks = generate_playbook_tasks(selected_checks) if 'selected_checks' in locals() else []
                
                # 백엔드 콘솔에 생성 정보 출력
                print(f"\n{'='*80}")
                print(f"📝 PLAYBOOK 생성 시작")
                print(f"{'='*80}")
                print(f"🎯 대상 서버: {active_servers}")
                print(f"📋 선택된 점검 항목: {len(playbook_tasks)}개")
                if playbook_tasks:
                    print("📄 포함될 파일들:")
                    for i, task in enumerate(playbook_tasks, 1):
                        print(f"   {i}. {task}")
                print(f"{'='*80}")
                
                # 플레이북 파일로 저장
                playbook_path, playbook_filename, result_folder_path = save_generated_playbook(active_servers, playbook_tasks)
                
                # inventory 파일 저장
                inventory_path = save_inventory_file(servers_info)
                
                # 백엔드 콘솔에 저장 완료 메시지
                print(f"✅ 플레이북 저장 완료: {playbook_path}")
                print(f"✅ 인벤토리 저장 완료: {inventory_path}")
                print(f"{'='*80}\n")
                
                # 세션 상태에 저장
                st.session_state.playbook_generated = True
                st.session_state.playbook_path = playbook_path
                st.session_state.inventory_path = inventory_path
                st.session_state.playbook_tasks = playbook_tasks
                st.session_state.selected_checks = selected_checks if 'selected_checks' in locals() else {}
                st.session_state.result_folder_path = result_folder_path  # 결과 폴더 경로 추가
                
                time.sleep(1)
                
                # 페이지 새로고침
                st.rerun()
    
    # 플레이북이 생성된 후 실행 단계
    if st.session_state.playbook_generated:
        # 생성된 플레이북 정보 표시
        st.success("✅ 플레이북 생성 및 저장 완료!")
        
        # 선택된 점검 항목 카운트
        total_checks = count_selected_checks(st.session_state.selected_checks)
        
        playbook_info = {
            "대상 서버": active_servers,
            "총 점검 항목": f"{total_checks}개",
            "점검 서비스": list(st.session_state.selected_checks.keys()),
            "생성된 플레이북": os.path.basename(st.session_state.playbook_path),
            "저장 경로": st.session_state.playbook_path,
            "inventory 파일": st.session_state.inventory_path,
            "결과 저장 폴더": st.session_state.result_folder_path,  # 결과 폴더 정보 추가
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
                    active_servers
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
                                print("🎉 스트림릿 UI에서도 실행 완료 확인됨")
                            else:
                                st.error(f"❌ 실행 실패 (종료 코드: {content})")
                                st.info(f"📄 에러 로그가 `logs/{log_filename}`에 저장되었습니다.")
                                print(f"❌ 스트림릿 UI에서도 실행 실패 확인됨 (코드: {content})")
                                
                        elif msg_type == 'error':
                            st.error(f"❌ 실행 오류: {content}")
                            st.info(f"📄 에러 로그가 `logs/{log_filename}`에 저장되었습니다.")
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
            st.session_state.result_folder_path= ""
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