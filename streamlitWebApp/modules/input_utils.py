import re
from collections import defaultdict

"""
취약점 점검 관련 유틸리티 함수들
"""

"""선택된 점검 항목 수 계산 (확장 버전)"""
def count_selected_checks(selected_checks, vulnerability_categories):
    total_checks = 0
    
    for service, selected in selected_checks.items():
        # 구조화된 선택 방식 (Server-Linux, PC-Linux, MySQL, Apache, Nginx, PHP)
        if service in ["Server-Linux", "PC-Linux", "MySQL", "Apache", "Nginx", "PHP"] and isinstance(selected, dict):
            if selected.get("all", False):
                # 전체 선택 시 해당 서비스의 모든 항목 수 추가
                total_checks += vulnerability_categories[service]["count"]
            else:
                # 개별 선택된 항목만 카운트
                categories = selected.get("categories", {})
                for category, items in categories.items():
                    if isinstance(items, dict):
                        total_checks += sum(1 for item_selected in items.values() if item_selected)
        
        # 단순 boolean 선택 방식 (SQLite, WebApp 등)
        elif selected and service in vulnerability_categories:
            total_checks += vulnerability_categories[service]["count"]
    
    return total_checks

""" Ansible PLAY RECAP 로그를 파싱하여 결과 통계를 반환 """
def parse_play_recap(log_lines):
    result_summary = {
        "성공한 태스크": 0,
        "변경된 설정": 0,
        "실패한 태스크": 0,
        "무시된 태스크": 0,    # 🆕 추가
        "접근 불가 서버": 0,
        "건너뛴 태스크": 0,
        "서버 상세": {}
    }
    
    # PLAY RECAP 섹션 찾기
    recap_started = False
    
    for line in log_lines:
        # PLAY RECAP 시작 감지
        if "PLAY RECAP" in line:
            recap_started = True
            continue
            
        # PLAY RECAP 이후의 서버별 결과 파싱
        if recap_started and ":" in line:
            # 타임스탬프 제거 ([14:19:07] 부분)
            clean_line = re.sub(r'^\[.*?\]\s*', '', line.strip())
            
            # 서버명과 결과 분리
            if ":" in clean_line and any(stat in clean_line for stat in ["ok=", "changed=", "failed=", "unreachable="]):
                parts = clean_line.split(":", 1)
                if len(parts) == 2:
                    server_name = parts[0].strip()
                    stats_part = parts[1].strip()
                    
                    # 각 통계 추출
                    stats = {}
                    patterns = {
                        'ok': r'ok=(\d+)',
                        'changed': r'changed=(\d+)', 
                        'unreachable': r'unreachable=(\d+)',
                        'failed': r'failed=(\d+)',
                        'skipped': r'skipped=(\d+)',
                        'rescued': r'rescued=(\d+)',
                        'ignored': r'ignored=(\d+)'
                    }
                    
                    for stat_name, pattern in patterns.items():
                        match = re.search(pattern, stats_part)
                        if match:
                            stats[stat_name] = int(match.group(1))
                        else:
                            stats[stat_name] = 0
                    
                    # 서버별 상세 정보 저장
                    result_summary["서버 상세"][server_name] = stats
                    
                    # 전체 통계에 합산
                    result_summary["성공한 태스크"] += stats.get('ok', 0)
                    result_summary["변경된 설정"] += stats.get('changed', 0)
                    result_summary["실패한 태스크"] += stats.get('failed', 0)
                    result_summary["무시된 태스크"] += stats.get('ignored', 0)    # 🆕 추가
                    result_summary["접근 불가 서버"] += stats.get('unreachable', 0)
                    result_summary["건너뛴 태스크"] += stats.get('skipped', 0)
    
    return result_summary
