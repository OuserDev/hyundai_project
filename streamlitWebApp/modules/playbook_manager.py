"""
Ansible 플레이북 생성 및 실행 관련 함수들 (import_playbook 방식 유지)
"""
import os
import yaml
import subprocess
import threading
import queue
from datetime import datetime

"""생성된 플레이북을 파일로 저장 (import_playbook 방식 유지)"""
def save_generated_playbook(active_servers, playbook_tasks, result_folder_path):
    # 결과 디렉토리를 미리 생성 (Streamlit에서)
    results_dir = os.path.join(result_folder_path, "results")
    os.makedirs(results_dir, exist_ok=True)
    print(f"📁 결과 디렉토리 미리 생성: {results_dir}")
    
    # 메인 플레이북 구조 생성 (import_playbook 방식)
    playbook_content = []
    
    # 첫 번째 플레이: 초기 설정 (연결성 테스트)
    main_play = {
        'name': 'KISA Security Check - Connectivity Test and Setup',
        'hosts': 'target_servers',
        'become': True,
        'gather_facts': True,
        'any_errors_fatal': False,  # 이 플레이에서 오류가 나도 다음 플레이북들 계속 실행
        'ignore_errors': True,        # 🆕 추가
        'ignore_unreachable': True,   # 🆕 추가
        'vars': {
            'result_directory': f"{result_folder_path}/results",
            'execution_timestamp': datetime.now().strftime("%Y%m%d_%H%M%S")
        },
        'tasks': [
            {
                'name': 'Create result directory on control node',
                'file': {
                    'path': f"{result_folder_path}/results",
                    'state': 'directory',
                    'mode': '0755'
                },
                'delegate_to': 'localhost',
                'run_once': True,
                'ignore_errors': True
            },
            {
                'name': 'Test connectivity to target hosts',
                'ping': {},
                'ignore_errors': True,
                'register': 'connectivity_test'
            },
            {
                'name': 'Log connectivity status',
                'debug': {
                    'msg': "Host {{ inventory_hostname }} connectivity: {{ 'SUCCESS' if connectivity_test is succeeded else 'FAILED' }}"
                },
                'ignore_errors': True
            }
        ]
    }
    playbook_content.append(main_play)
    
    # import_playbook들 추가 (변수 전달)
    for task_file in playbook_tasks:
        # 태스크 코드 추출 (파일명에서)
        task_code = task_file.replace('.yml', '')
        
        import_entry = {
            'import_playbook': f"../../tasks/{task_file}",
            'vars': {
                'result_json_path': f"{os.path.abspath(result_folder_path)}/results/{task_code}_{{{{ inventory_hostname }}}}.json"
            }
        }
        playbook_content.append(import_entry)
    
    # 파일명 생성 (result_folder_path에서 타임스탬프 추출)
    folder_name = os.path.basename(result_folder_path)
    timestamp = folder_name.replace("playbook_result_", "")
    
    filename = f"security_check_{timestamp}.yml"
    filepath = os.path.join(result_folder_path, filename)
    
    # YAML 파일로 저장
    with open(filepath, 'w', encoding='utf-8') as f:
        yaml.dump(playbook_content, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    
    # 백엔드 콘솔에 생성된 플레이북 내용 출력
    print(f"\n{'='*80}")
    print(f"📝 생성된 플레이북 내용 (import_playbook 방식):")
    print(f"{'='*80}")
    with open(filepath, 'r', encoding='utf-8') as f:
        print(f.read())
    print(f"{'='*80}\n")
    
    # 타임스탬프도 함께 반환
    return filepath, filename, timestamp

"""백엔드에서 Ansible 플레이북 실행 (ansible.cfg 의존)"""
def execute_ansible_playbook(playbook_path, inventory_path, limit_hosts, result_folder_path, timestamp):
    # 로그 파일 경로 생성 (플레이북과 동일한 타임스탬프 사용)
    log_filename = f"ansible_execute_log_{timestamp}.log"
    log_path = os.path.join("logs", log_filename)
    
    # logs 디렉터리 생성
    os.makedirs("logs", exist_ok=True)
    
    # ansible.cfg가 있는지 확인
    ansible_cfg_path = "ansible.cfg"
    if not os.path.exists(ansible_cfg_path):
        print(f"⚠️ ansible.cfg 파일이 없습니다. 기본 설정으로 실행됩니다.")
        print(f"📋 권장: 프로젝트 루트에 ansible.cfg 파일을 생성하세요.")
    else:
        print(f"✅ ansible.cfg 파일 발견: {ansible_cfg_path}")
    
    # 실행 명령어 구성 (표준 옵션만 사용)
    cmd = [
        'ansible-playbook',
        '-i', inventory_path,
        playbook_path,
        '--limit', 'target_servers',
        '--forks', '5',  # 안정적인 병렬 실행 수
        '-v'  # 기본 로그 레벨
    ]
    
    # 백엔드 콘솔에 명령어 출력
    print(f"\n{'='*80}")
    print(f"🚀 ANSIBLE PLAYBOOK 실행 시작 (ansible.cfg 전역 설정 의존)")
    print(f"{'='*80}")
    print(f"📝 명령어: {' '.join(cmd)}")
    print(f"📂 플레이북: {playbook_path}")
    print(f"📋 인벤토리: {inventory_path}")
    print(f"🎯 대상 그룹: target_servers")
    print(f"⚙️ 설정: ansible.cfg의 any_errors_fatal=False 전역 설정 적용")
    print(f"📄 로그 파일: {log_path} (타임스탬프: {timestamp})")
    print(f"📁 결과 저장 폴더: {result_folder_path}/results")
    print(f"{'='*80}\n")
    
    # 실행 결과를 담을 큐
    output_queue = queue.Queue()
    
    def run_command():
        log_lines = []  # 로그 파일에 저장할 내용
        
        try:
            # 로그 파일 헤더 작성
            log_header = [
                f"=== Ansible Playbook 실행 로그 (ansible.cfg 설정, 타임스탬프: {timestamp}) ===",
                f"실행 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"명령어: {' '.join(cmd)}",
                f"플레이북: {playbook_path}",
                f"인벤토리: {inventory_path}",
                f"대상 그룹: target_servers",
                f"설정: ansible.cfg 전역 설정 (any_errors_fatal=False)",
                f"결과 저장: {result_folder_path}/results",
                f"{'='*50}",
                ""
            ]
            log_lines.extend(log_header)
            
            # 환경 변수 설정 (SSH 연결 최적화)
            env = os.environ.copy()
            env.update({
                'ANSIBLE_HOST_KEY_CHECKING': 'False',
                'ANSIBLE_SSH_RETRIES': '2',
                'ANSIBLE_TIMEOUT': '30'
            })
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                cwd=os.getcwd(),
                env=env
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
            completion_msg = f"실행 완료 - 종료 코드: {return_code} (ansible.cfg 설정, 타임스탬프: {timestamp})"
            log_lines.append(f"\n{'='*50}")
            log_lines.append(f"[{datetime.now().strftime('%H:%M:%S')}] {completion_msg}")
            log_lines.append(f"실행 종료 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # 종료 코드별 처리 (ansible.cfg 설정에 따라 대부분 성공으로 처리됨)
            if return_code == 0:
                log_lines.append(f"✅ 플레이북 실행이 성공적으로 완료되었습니다.")
                success = True
            elif return_code == 2:
                log_lines.append(f"⚠️ 일부 태스크에서 실패가 있었지만 ansible.cfg 설정으로 계속 진행되었습니다.")
                log_lines.append(f"📊 PLAY RECAP에서 개별 실패 내역을 확인하세요.")
                success = True  # ansible.cfg 설정으로 성공으로 간주
            elif return_code == 4:
                log_lines.append(f"🔌 일부 호스트에 접근할 수 없었지만 가능한 호스트에서는 실행되었습니다.")
                success = True  # 부분 성공으로 간주
            else:
                log_lines.append(f"❌ 심각한 오류가 발생했습니다 (코드: {return_code}).")
                success = False
            
            # 로그 파일에 저장
            try:
                with open(log_path, 'w', encoding='utf-8') as log_file:
                    log_file.write('\n'.join(log_lines))
                print(f"📄 로그 저장 완료: {log_path}")
            except Exception as log_error:
                print(f"❌ 로그 파일 저장 실패: {str(log_error)}")
            
            # 백엔드 콘솔에 완료 메시지
            print(f"\n{'='*80}")
            if success:
                print(f"✅ ANSIBLE PLAYBOOK 실행 완료 (종료 코드: {return_code}, 타임스탬프: {timestamp})")
                print(f"📁 결과 파일들이 다음 위치에 저장되었습니다: {result_folder_path}/results/")
            else:
                print(f"❌ ANSIBLE PLAYBOOK 실행 오류 (종료 코드: {return_code}, 타임스탬프: {timestamp})")
            print(f"📄 로그: {log_path}")
            print(f"⚙️ ansible.cfg 설정으로 개별 태스크 실패는 무시되었습니다.")
            print(f"{'='*80}\n")
            
            # 대부분의 경우 성공으로 반환 (ansible.cfg 설정 덕분)
            final_return_code = 0 if success else return_code
            output_queue.put(('finished', final_return_code))
            
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

"""KISA 점검 항목 설명을 파일명으로 변환"""
def generate_task_filename(item_description, filename_mapping):
    item_code = item_description.split(":")[0].strip()
    return filename_mapping.get(item_code, f"{item_code}_security_check.yml")

"""선택된 점검 항목에 따라 플레이북 태스크 생성 (확장 버전)"""
def generate_playbook_tasks(selected_checks, filename_mapping, vulnerability_categories, analysis_mode="unified", active_servers=None, server_specific_checks=None):
    playbook_tasks = []
    
    if analysis_mode == "server_specific" and server_specific_checks:
        # 🔧 개선: 실제 서버별 선택 정보 사용
        all_tasks = set()  # 중복 제거
        
        for server_name, server_checks in server_specific_checks.items():
            server_tasks = []
            
            for service, selected in server_checks.items():
                if service in vulnerability_categories and isinstance(selected, dict):
                    if selected.get("all", False):
                        # 전체 선택 시 모든 항목 포함
                        for category, items in vulnerability_categories[service]["subcategories"].items():
                            for item in items:
                                task_file = generate_task_filename(item, filename_mapping)
                                server_tasks.append(task_file)
                    else:
                        # 개별 선택된 항목만 포함
                        categories = selected.get("categories", {})
                        for category, items in categories.items():
                            if isinstance(items, dict):
                                for item, item_selected in items.items():
                                    if item_selected:
                                        task_file = generate_task_filename(item, filename_mapping)
                                        server_tasks.append(task_file)
            
            # 모든 태스크를 전체 목록에 추가 (중복 제거)
            all_tasks.update(server_tasks)
        
        return list(all_tasks)
    
    else:
        for service, selected in selected_checks.items():
            if service == "Server-Linux" and isinstance(selected, dict):
                if selected["all"]:
                    # 전체 선택 시 모든 항목 포함
                    for category, items in vulnerability_categories["Server-Linux"]["subcategories"].items():
                        for item in items:
                            task_file = generate_task_filename(item, filename_mapping)
                            playbook_tasks.append(task_file)
                else:
                    # 개별 선택된 항목만 포함
                    for category, items in selected["categories"].items():
                        if isinstance(items, dict):
                            for item, item_selected in items.items():
                                if item_selected:
                                    task_file = generate_task_filename(item, filename_mapping)
                                    playbook_tasks.append(task_file)
            
            elif service == "PC-Linux" and isinstance(selected, dict):
                if selected["all"]:
                    # 전체 선택 시 모든 항목 포함
                    for category, items in vulnerability_categories["PC-Linux"]["subcategories"].items():
                        for item in items:
                            task_file = generate_task_filename(item, filename_mapping)
                            playbook_tasks.append(task_file)
                else:
                    # 개별 선택된 항목만 포함
                    for category, items in selected["categories"].items():
                        if isinstance(items, dict):
                            for item, item_selected in items.items():
                                if item_selected:
                                    task_file = generate_task_filename(item, filename_mapping)
                                    playbook_tasks.append(task_file)
            
            elif service == "MySQL" and isinstance(selected, dict):
                if selected["all"]:
                    # 전체 선택 시 모든 항목 포함
                    for category, items in vulnerability_categories["MySQL"]["subcategories"].items():
                        for item in items:
                            task_file = generate_task_filename(item, filename_mapping)
                            playbook_tasks.append(task_file)
                else:
                    # 개별 선택된 항목만 포함
                    for category, items in selected["categories"].items():
                        if isinstance(items, dict):
                            for item, item_selected in items.items():
                                if item_selected:
                                    task_file = generate_task_filename(item, filename_mapping)
                                    playbook_tasks.append(task_file)
            
            elif service == "Apache" and isinstance(selected, dict):
                if selected["all"]:
                    # 전체 선택 시 모든 항목 포함
                    for category, items in vulnerability_categories["Apache"]["subcategories"].items():
                        for item in items:
                            task_file = generate_task_filename(item, filename_mapping)
                            playbook_tasks.append(task_file)
                else:
                    # 개별 선택된 항목만 포함
                    for category, items in selected["categories"].items():
                        if isinstance(items, dict):
                            for item, item_selected in items.items():
                                if item_selected:
                                    task_file = generate_task_filename(item, filename_mapping)
                                    playbook_tasks.append(task_file)
            
            elif service == "Nginx" and isinstance(selected, dict):
                if selected["all"]:
                    # 전체 선택 시 모든 항목 포함
                    for category, items in vulnerability_categories["Nginx"]["subcategories"].items():
                        for item in items:
                            task_file = generate_task_filename(item, filename_mapping)
                            playbook_tasks.append(task_file)
                else:
                    # 개별 선택된 항목만 포함
                    for category, items in selected["categories"].items():
                        if isinstance(items, dict):
                            for item, item_selected in items.items():
                                if item_selected:
                                    task_file = generate_task_filename(item, filename_mapping)
                                    playbook_tasks.append(task_file)
            
            elif service == "PHP" and isinstance(selected, dict):
                if selected["all"]:
                    # 전체 선택 시 모든 항목 포함
                    for category, items in vulnerability_categories["PHP"]["subcategories"].items():
                        for item in items:
                            task_file = generate_task_filename(item, filename_mapping)
                            playbook_tasks.append(task_file)
                else:
                    # 개별 선택된 항목만 포함
                    for category, items in selected["categories"].items():
                        if isinstance(items, dict):
                            for item, item_selected in items.items():
                                if item_selected:
                                    task_file = generate_task_filename(item, filename_mapping)
                                    playbook_tasks.append(task_file)
            pass 
    return playbook_tasks