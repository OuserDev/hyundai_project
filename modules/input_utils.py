"""
취약점 점검 관련 유틸리티 함수들
"""

"""선택된 점검 항목 수 계산"""
def count_selected_checks(selected_checks,vulnerability_categories):
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