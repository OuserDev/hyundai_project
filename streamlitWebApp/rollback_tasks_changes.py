import os
import glob
import re

def rollback_changes():
    """백업 파일로부터 원본 복구 및 result_json_path 제거"""
    backup_files = glob.glob("tasks/*.backup")
    
    if not backup_files:
        print("📁 백업 파일이 없습니다. 대신 result_json_path만 제거합니다.")
        # 백업이 없으면 현재 파일들에서 result_json_path만 제거
        task_files = glob.glob("tasks/*.yml")
        for task_file in task_files:
            remove_json_path_only(task_file)
        return
    
    for backup_file in backup_files:
        original_file = backup_file.replace('.backup', '')
        
        try:
            with open(backup_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 🆕 복구하면서 result_json_path 라인 제거
            lines = content.split('\n')
            filtered_lines = []
            removed_json_path = False
            
            for line in lines:
                if 'result_json_path:' in line and '/tmp/security_report_' in line:
                    removed_json_path = True
                    continue
                filtered_lines.append(line)
            
            # 필터링된 내용으로 저장
            final_content = '\n'.join(filtered_lines)
            
            with open(original_file, 'w', encoding='utf-8') as f:
                f.write(final_content)
            
            os.remove(backup_file)
            
            result_msg = f"✅ {original_file}: 롤백 완료"
            if removed_json_path:
                result_msg += " + result_json_path 제거"
            print(result_msg)
            
        except Exception as e:
            print(f"❌ {original_file}: 롤백 실패 - {str(e)}")

def remove_json_path_only(task_file):
    """개별 파일에서 result_json_path만 제거"""
    try:
        with open(task_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        filtered_lines = []
        removed_json_path = False
        
        for line in lines:
            if 'result_json_path:' in line and '/tmp/security_report_' in line:
                removed_json_path = True
                continue
            filtered_lines.append(line)
        
        if removed_json_path:
            with open(task_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(filtered_lines))
            print(f"🗑️ {task_file}: result_json_path 라인 제거됨")
        
    except Exception as e:
        print(f"❌ {task_file}: 처리 실패 - {str(e)}")

if __name__ == "__main__":
    rollback_changes()