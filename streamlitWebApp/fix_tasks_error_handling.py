import os
import glob
import re

def add_error_handling_to_tasks():
    """모든 태스크 파일에 오류 처리 설정 추가"""
    
    tasks_dir = "tasks"
    if not os.path.exists(tasks_dir):
        print(f"❌ {tasks_dir} 폴더를 찾을 수 없습니다.")
        return
    
    task_files = glob.glob(f"{tasks_dir}/*.yml")
    print(f"📁 {len(task_files)}개 태스크 파일 발견")
    
    modified_count = 0
    
def add_error_handling_to_tasks():
    """모든 태스크 파일에 오류 처리 설정 추가 및 불필요한 result_json_path 제거"""
    
    tasks_dir = "tasks"
    if not os.path.exists(tasks_dir):
        print(f"❌ {tasks_dir} 폴더를 찾을 수 없습니다.")
        return
    
    task_files = glob.glob(f"{tasks_dir}/*.yml")
    print(f"📁 {len(task_files)}개 태스크 파일 발견")
    
    modified_count = 0
    
    for task_file in task_files:
        try:
            with open(task_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 🆕 result_json_path 라인 제거
            lines = content.split('\n')
            filtered_lines = []
            removed_json_path = False
            
            for line in lines:
                # result_json_path가 포함된 라인 제거
                if 'result_json_path:' in line and '/tmp/security_report_' in line:
                    removed_json_path = True
                    continue
                filtered_lines.append(line)
            
            # 필터링된 내용으로 업데이트
            content = '\n'.join(filtered_lines)
            
            # 이미 ignore_errors가 있는지 확인
            if 'ignore_errors:' in content or 'ignore_unreachable:' in content:
                if removed_json_path:
                    # JSON path만 제거된 경우라도 저장
                    with open(task_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    print(f"🗑️ {task_file}: result_json_path 라인 제거됨")
                else:
                    print(f"⏭️ {task_file}: 이미 오류 처리 설정이 있음")
                continue
            
            # YAML 헤더 부분 찾기 (hosts: 라인 다음에 추가)
            lines = content.split('\n')
            new_lines = []
            hosts_found = False
            settings_added = False
            
            for line in lines:
                new_lines.append(line)
                
                # hosts: 라인을 찾은 후 설정 추가
                if re.match(r'^\s*hosts:\s+', line) and not settings_added:
                    # 들여쓰기 수준 확인
                    indent = len(line) - len(line.lstrip())
                    indent_str = ' ' * indent
                    
                    # 오류 처리 설정 추가
                    new_lines.append(f"{indent_str}ignore_errors: true")
                    new_lines.append(f"{indent_str}ignore_unreachable: true")
                    new_lines.append(f"{indent_str}any_errors_fatal: false")
                    settings_added = True
                    hosts_found = True
            
            if hosts_found and settings_added:
                # 파일 백업
                backup_file = f"{task_file}.backup"
                with open(backup_file, 'w', encoding='utf-8') as f:
                    f.write(content)  # 원본 내용 백업 (JSON path 제거 전)
                
                # 수정된 내용 저장
                with open(task_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(new_lines))
                
                result_msg = f"✅ {task_file}: 오류 처리 설정 추가 완료"
                if removed_json_path:
                    result_msg += " + result_json_path 제거"
                print(result_msg)
                modified_count += 1
            else:
                print(f"⚠️ {task_file}: hosts 라인을 찾을 수 없음")
                
        except Exception as e:
            print(f"❌ {task_file}: 처리 실패 - {str(e)}")
    
    
    print(f"\n🎉 총 {modified_count}개 파일 수정 완료")
    print(f"💾 원본 파일은 .backup 확장자로 백업되었습니다.")

if __name__ == "__main__":
    add_error_handling_to_tasks()