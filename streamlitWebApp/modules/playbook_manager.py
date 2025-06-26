"""
Ansible 플레이북 생성 및 실행 관련 함수들
"""
import os
import yaml
import subprocess
import threading
import queue
from datetime import datetime

"""생성된 플레이북을 파일로 저장 (기존 방식 + 오류 처리)"""
def save_generated_playbook(active_servers, playbook_tasks, result_folder_path):
    # 결과 디렉토리를 미리 생성 (Streamlit에서)
    results_dir = os.path.join(result_folder_path, "results")
    os.makedirs(results_dir, exist_ok=True)
    print(f"📁 결과 디렉토리 미리 생성: {results_dir}")
    
    # 메인 플레이북 구조 생성 (오류 처리 추가)
    playbook_content = []
    
    # 첫 번째 플레이: 초기 설정 (오류 처리 설정 추가)
    main_play = {
        'name': 'KISA Security Vulnerability Check with Error Handling',
        'hosts': 'target_servers',
        'become': True,
        'gather_facts': True,
        'ignore_errors': True,  # 전체 플레이에서 오류 무시
        'any_errors_fatal': False,  # 개별 호스트 오류로 전체 중단 방지
        'vars': {
            'result_directory': f"{result_folder_path}/results",
            'execution_timestamp': datetime.now().strftime("%Y%m%d_%H%M%S")
        }
    }
    playbook_content.append(main_play)
    
    # import_playbook들 추가 (변수 전달 + 오류 처리)
    for task_file in playbook_tasks:
        # 태스크 코드 추출 (파일명에서)
        task_code = task_file.replace('.yml', '')
        
        import_entry = {
            'import_playbook': f"../../tasks/{task_file}",
            'ignore_errors': True,  # 각 import_playbook에서 오류 무시
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
    print(f"📝 생성된 오류 처리 플레이북 내용:")
    print(f"{'='*80}")
    with open(filepath, 'r', encoding='utf-8') as f:
        print(f.read())
    print(f"{'='*80}\n")
    
    # 타임스탬프도 함께 반환
    return filepath, filename, timestamp

"""백엔드에서 Ansible 플레이북 실행 (오류 무시 옵션 포함)"""
def execute_ansible_playbook(playbook_path, inventory_path, limit_hosts, result_folder_path, timestamp):
    # 로그 파일 경로 생성 (플레이북과 동일한 타임스탬프 사용)
    log_filename = f"ansible_execute_log_{timestamp}.log"
    log_path = os.path.join("logs", log_filename)
    
    # logs 디렉터리 생성
    os.makedirs("logs", exist_ok=True)
    
    # 실행 명령어 구성 (오류 무시 옵션 추가)
    cmd = [
        'ansible-playbook',
        '-i', inventory_path,
        playbook_path,
        '--limit', 'target_servers',
        '--ignore-errors',  # ← 핵심 추가! 개별 플레이북 실패해도 다음 계속 실행
        '-v'
    ]
    
    # 백엔드 콘솔에 명령어 출력
    print(f"\n{'='*80}")
    print(f"🚀 ANSIBLE PLAYBOOK 실행 시작 (오류 무시 모드)")
    print(f"{'='*80}")
    print(f"📝 명령어: {' '.join(cmd)}")
    print(f"📂 플레이북: {playbook_path}")
    print(f"📋 인벤토리: {inventory_path}")
    print(f"🎯 대상 그룹: target_servers")
    print(f"⚠️ 오류 처리: 개별 태스크 실패해도 다음 태스크 계속 진행")
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
                f"=== Ansible Playbook 실행 로그 (오류 무시 모드, 타임스탬프: {timestamp}) ===",
                f"실행 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"명령어: {' '.join(cmd)}",
                f"플레이북: {playbook_path}",
                f"인벤토리: {inventory_path}",
                f"대상 그룹: target_servers",
                f"오류 처리: --ignore-errors 옵션 사용 (개별 실패해도 계속 진행)",
                f"결과 저장: {result_folder_path}/results",
                f"{'='*50}",
                ""
            ]
            log_lines.extend(log_header)
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                cwd=os.getcwd()  # 현재 작업 디렉토리 명시적으로 설정
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
            completion_msg = f"실행 완료 - 종료 코드: {return_code} (오류 무시 모드, 타임스탬프: {timestamp})"
            log_lines.append(f"\n{'='*50}")
            log_lines.append(f"[{datetime.now().strftime('%H:%M:%S')}] {completion_msg}")
            log_lines.append(f"실행 종료 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # --ignore-errors 모드에서는 개별 실패가 있어도 성공으로 간주
            if return_code == 0:
                log_lines.append(f"✅ 모든 태스크가 성공적으로 완료되었습니다.")
            elif return_code == 2:
                log_lines.append(f"⚠️ 일부 태스크가 실패했지만 --ignore-errors 옵션으로 계속 진행되었습니다.")
                log_lines.append(f"📊 PLAY RECAP에서 개별 실패 내역을 확인하세요.")
            else:
                log_lines.append(f"❌ 예상치 못한 오류가 발생했습니다.")
            
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
                print(f"✅ ANSIBLE PLAYBOOK 실행 완료 (종료 코드: {return_code}, 타임스탬프: {timestamp})")
                print(f"📁 결과 파일들이 다음 위치에 저장되었습니다: {result_folder_path}/results/")
            elif return_code == 2:
                print(f"⚠️ ANSIBLE PLAYBOOK 일부 실패 (종료 코드: {return_code}, 타임스탬프: {timestamp})")
                print(f"📊 --ignore-errors 옵션으로 모든 태스크가 실행되었습니다.")
                print(f"📁 결과 파일들: {result_folder_path}/results/")
            else:
                print(f"❌ ANSIBLE PLAYBOOK 실행 오류 (종료 코드: {return_code}, 타임스탬프: {timestamp})")
            print(f"📄 로그: {log_path}")
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

"""KISA 점검 항목 설명을 파일명으로 변환"""
def generate_task_filename(item_description, filename_mapping):
    item_code = item_description.split(":")[0].strip()
    return filename_mapping.get(item_code, f"{item_code}_security_check.yml")

"""선택된 점검 항목에 따라 플레이북 태스크 생성 (확장 버전)"""
def generate_playbook_tasks(selected_checks, filename_mapping, vulnerability_categories):
    playbook_tasks = []
    
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
 
    return playbook_tasks