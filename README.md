# hyundai_project

# Ansible 서버 취약점 자동 점검 시스템

## 🎯 프로젝트 개요
Ansible + Python을 활용한 서버 보안 취약점 자동 점검 및 보고서 생성 시스템

## 🔧 주요 기능
- **자동 취약점 점검**: KISA 가이드라인 기반 83개 항목 검사
- **다중 분석**: 정적/동적/네트워크 분석 지원
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
- **분석도구**: 정적 설정 점검, 웹앱 동적 테스트, 네트워크 스캔

## 🚀 개발 일정
- **Phase 1** (~6/19): Ansible 환경 구축
- **Phase 2** (~6/23): 웹 인터페이스 개발  
- **Phase 3** (~6/27): 분석 기능 확장
- **Phase 4** (~6/29): 보고서 시스템 완성

## 👥 Team 2
윤석빈, 김태근, 이대희, 박부성, 김선혁

## 프로젝트 디렉토리
```
├── 📁 inventories/                     # Ansible inventory 파일들 (ignore 처리)
│   └── 📄 inventory_20250618_101836.ini
│
├── 📁 logs/                            # 실행 로그 파일들 (ignore 처리)
│   └── (실행 로그들)
│
├── 📁 playbooks/                       # 동적 생성된 플레이북들 (ignore 처리)
│   └── 📄 security_check_20250618_101836.yml
│
├── 📁 tasks/                           # 개별 KISA 점검 태스크들
│   ├── 📄 1_1_8_etc_passwd_permissions.yml
│   ├── ...
│
├── 📄 .gitignore                       # Git 무시 파일 목록
├── 📄 README.md                        # 프로젝트 설명서
├── 📄 requirements.txt                 # Python 의존성 패키지
├── 📄 streamlit_app.py                 # 메인 Streamlit 애플리케이션
├── 📄 filename_mapping.json            # KISA 코드 → 파일명 매핑
└── 📄 vulnerability_categories.json    # 취약점 카테고리 정의
```
