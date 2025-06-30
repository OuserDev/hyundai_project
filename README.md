# hyundai_project

# Ansible 서버 취약점 자동 점검 시스템

## 🎯 프로젝트 개요
Ansible + Python을 활용한 서버 보안 취약점 자동 점검 및 보고서 생성 시스템

## 🔧 주요 기능
- **자동 취약점 점검**: KISA 가이드라인 기반 77개 항목 검사
- **다중 분석**: 취약점 점검 및 이벤트 기반 공격탐지 시스템
- **웹 인터페이스**: Streamlit 기반 직관적 UI
- **자동 보고서**: Python 기반 시각화 리포트 생성

## 🛠️ 기술 스택
- **Backend**: Ansible, Python
- **Frontend**: Streamlit
- **Analysis**: nmap, NSE Scripts
- **Targets**: Linux, MySQL, Apache, Nginx, PHP

## 📋 지원 환경
- **서버**: PC-Linux, Server-Linux
- **웹서비스**: MySQL, Apache, Nginx, PHP, SQLite
- **분석도구**: 취약점 점검, 이벤트 기반 공격 탐지 시스템

## 🚀 개발 일정
- **Phase 1** (~6/19): Ansible 환경 구축
- **Phase 2** (~6/23): 웹 인터페이스 개발  
- **Phase 3** (~6/27): 분석 기능 확장
- **Phase 4** (~6/29): 보고서 시스템 완성

## 👥 Team 2
윤석빈, 김태곤, 박부성, 김선혁

## 프로젝트 디렉토리
```
📁 pjt/                                     # 루트 디렉토리
├── 📁 logs/                                # Ansible 실행 로그 파일들 (ignore 처리)
│   └── 📄 ansible_execute_log_20250619_141836.log
│
├── 📁 modules/                             # 모듈화된 함수들
│   ├── 📁 __pycache__/
│   ├── 📄 __init__.py
│   ├── 📄 input_utils.py                   # 취약점 관련 유틸리티 함수들
│   ├── 📄 inventory_handler.py             # inventory 파일 파싱/생성 관련
│   └── 📄 playbook_manager.py              # 플레이북 생성/실행 관련
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
├── 📄 streamlit_app.py                     # 메인 Streamlit
├── 📄 filename_mapping.json                # KISA 코드 → 파일명 매핑
└── 📄 vulnerability_categories.json        # 취약점 카테고리 정의
```
