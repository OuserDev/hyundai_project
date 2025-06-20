"""
Inventory 파일 처리 관련 함수들
"""
import os
from datetime import datetime

"""inventory.ini 파일을 파싱하여 서버 정보 추출"""
def parse_inventory_file(file_content):
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

"""서버 정보를 inventory 파일로 저장 (선택된 서버들을 target_servers 그룹으로 설정)"""
def save_inventory_file(servers_info, selected_servers, result_folder_path):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    inventory_filename = f"inventory_{timestamp}.ini"
    inventory_path = os.path.join(result_folder_path, inventory_filename)
    
    print(f"\n=== INVENTORY 파일 생성 ===")
    print(f"파일 경로: {inventory_path}")
    print(f"선택된 서버들: {selected_servers}")
    
    inventory_content = []
    groups = {}
    
    # 선택된 서버들만 필터링
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
    
    # 전역 변수와 개별 변수 구분
    true_global_vars = {}
    server_specific_vars = set()
    
    # 먼저 각 서버별로 정의된 변수들을 수집
    for server_name, info in filtered_servers_info.items():
        ansible_vars = info.get('ansible_vars', {})
        for var_name in ansible_vars.keys():
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
