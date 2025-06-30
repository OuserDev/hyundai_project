![image](https://github.com/user-attachments/assets/27435c3d-9746-4c3c-a602-210ebf28f1f3)

# 🔒 Askable: Ansible 기반 보안 자동화 플랫폼
KISA 가이드라인 기반 취약점 점검 + 실시간 공격 탐지

## 👥 Development Team 2
윤석빈(팀장), 김태곤, 박부성, 김선혁, 이대희

---

## 🎯 핵심 기능

- **취약점 점검**: KISA 77개 항목 자동 진단 및 조치
- **공격 탐지**: PSAD(포트스캔) + fail2ban(SSH브루트포스) + WebMonitor(SQL인젝션)
- **다종/다중 서버 점검**: 서버별 맞춤형 점검 항목 선택 가능
- **자동 대응**: 공격 탐지 시 모든 관리 서버에 IP 자동 차단

## 🎛️ 사용법

1. 로그인: admin/admin (관리자) 또는 guest/guest (읽기전용)<br>
2. 취약점 점검: inventory 업로드 → 서버/항목 선택 → 동적 플레이북 생성 -> 실행<br>
3. 공격 탐지: 리스너 시작 → 공격 시뮬레이션 → 새로고침 → 자동 차단 확인

## 🏆 특장점
- **에이전트리스**: SSH만으로 모든 서버 점검 (별도 설치 불필요)
- **KISA 표준**: 한국 환경 특화 77개 항목 완벽 지원
- **실시간 대응**: 한 서버 공격 탐지 → 전체 네트워크 자동 보호
- **맞춤형 점검**: 서버별로 필요한 점검만 선택 실행

## 🚀 빠른 시작

### 설치
```bash
git clone https://github.com/foiscs/hyundai_project.git
cd hyundai_project

# micromamba 설치 (또는 conda 사용)
curl -Ls https://micro.mamba.pm/api/micromamba/linux-64/latest | tar -xvj bin/micromamba
./bin/micromamba shell init -s bash -p ~/micromamba
source ~/.bashrc

# 의존성 설치
pip install -r requirements.txt

# 실행
streamlit run streamlit_app.py
```

### 📝 Inventory 파일 형식
```
[webservers]
web1 ansible_host=192.168.1.10 ansible_user=ubuntu ansible_port=22 ansible_become_pass=password

[databases]  
db1 ansible_host=192.168.1.20 ansible_user=centos ansible_port=22 ansible_become_pass=password

[all:vars]
ansible_ssh_private_key_file=~/.ssh/id_rsa
ansible_python_interpreter=/usr/bin/python3
```
![image](https://github.com/user-attachments/assets/e4dd9dd8-f622-49c2-8b12-44bc4803815d)

## 프로젝트 디렉토리
```
📁 askable                                  # 공격 탐지 전용 모듈
📁 WebSite                                  # 웹 서비스 (Managed Node)
📁 Apache & Linux & MySQL & NginX & PHP_Playbook        # 원본 작업 플레이북
📁 StreamlitWebApp                          # 웹 애플리케이션
├── 📁 logs/                                # Ansible 실행 로그 파일들 (ignore 처리)
│   └── 📄 ansible_execute_log_20250619_141836.log
│
├── 📁 modules/                             # 모듈화된 함수들
│   ├── 📁 __pycache__/
│   ├── 📄 __init__.py
│   ├── 📄 input_utils.py                   # 취약점 관련 유틸리티 함수들
│   ├── 📄 inventory_handler.py             # inventory 파일 파싱/생성 관련
│   └── 📄 playbook_manager.py              # 플레이북 생성/실행 관련
│   └── 📄 history_manager.py               # 사이드바&결과리포트 관련
│
├── 📁 playbooks/                           # 동적 생성된 플레이북 & 인벤토리 (ignore 처리)
│   └── 📁 playbook_result_20250619_141833/
│       ├── 📁 results/                     # JSON 결과 파일들이 저장될 위치
│       ├── 📄 inventory_20250619_141833.ini
│       └── 📄 security_check_20250619_141833.yml
│
├── 📁 tasks/                               # 개별 KISA 점검 태스크들
│   ├── 📄 1_1_1_disable_root_ssh.yml
│   └── 📄 ...
│
├── 📄 README.md                            # 프로젝트 설명서
├── 📄 requirements.txt                     # Python 의존성 패키지
├── 📄 streamlit_app.py                     # 메인 Streamlit 애플리케이션 & 취약점 점검 페이지
├── 📄 dynamic_analysis.py                  # 공격 탐지 페이지
├── 📄 analysis_report.py			              # 분석 결과 페이지
├── 📄 filename_mapping.json                # KISA 코드 → 파일명 매핑
└── 📄 vulnerability_categories.json        # 취약점 카테고리 정의
└── 📄 ansible.cfg				# Ansible 설정
└── 📄 portscan.yml , ssh_fail.yml , WebAttackTest.yml			# 공격 탐지 전용 플레이북 (네트워크 공격, SSH 브루트 포스, SQL 인젝션)
```
