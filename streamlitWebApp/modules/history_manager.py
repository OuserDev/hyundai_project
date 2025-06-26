import os
import glob
import re
import streamlit as st
from datetime import datetime

"""기존 분석 기록 확인 및 디버깅"""
def debug_existing_logs():
    print("\n=== 기존 분석 기록 스캔 시작 ===")
    
    # 1. logs 폴더 확인
    if os.path.exists("logs"):
        print("✅ logs 폴더 존재")
        log_files = glob.glob("logs/*.log")
        print(f"📄 logs 폴더 내 .log 파일 수: {len(log_files)}")
        
        ansible_logs = glob.glob("logs/ansible_execute_log_*.log")
        print(f"📋 ansible_execute_log_*.log 파일 수: {len(ansible_logs)}")
        
        if ansible_logs:
            print("🔍 발견된 Ansible 로그 파일들:")
            for log_file in sorted(ansible_logs):
                print(f"  - {log_file}")
                
                # 타임스탬프 추출 테스트
                filename = os.path.basename(log_file)
                timestamp_match = re.search(r'ansible_execute_log_(\d{8}_\d{6})\.log', filename)
                if timestamp_match:
                    timestamp = timestamp_match.group(1)
                    print(f"    → 타임스탬프: {timestamp}")
                    
                    # 해당 결과 폴더 확인
                    result_folder = f"playbooks/playbook_result_{timestamp}"
                    if os.path.exists(result_folder):
                        print(f"    → 결과 폴더 존재: {result_folder}")
                        
                        # JSON 결과 파일 확인
                        results_path = f"{result_folder}/results"
                        if os.path.exists(results_path):
                            json_files = glob.glob(f"{results_path}/*.json")
                            print(f"    → JSON 결과 파일 수: {len(json_files)}")
                        else:
                            print(f"    → ❌ results 폴더 없음: {results_path}")
                    else:
                        print(f"    → ❌ 결과 폴더 없음: {result_folder}")
                else:
                    print(f"    → ❌ 타임스탬프 추출 실패: {filename}")
        else:
            print("📭 Ansible 실행 로그 파일 없음")
    else:
        print("❌ logs 폴더 없음")
    
    # 2. playbooks 폴더 확인
    if os.path.exists("playbooks"):
        print("\n✅ playbooks 폴더 존재")
        result_folders = glob.glob("playbooks/playbook_result_*")
        print(f"📁 playbook_result_* 폴더 수: {len(result_folders)}")
        
        if result_folders:
            print("🔍 발견된 결과 폴더들:")
            for folder in sorted(result_folders):
                print(f"  - {folder}")
                
                # results 하위 폴더 확인
                results_path = f"{folder}/results"
                if os.path.exists(results_path):
                    json_files = glob.glob(f"{results_path}/*.json")
                    print(f"    → JSON 파일 수: {len(json_files)}")
                else:
                    print(f"    → ❌ results 하위폴더 없음")
        else:
            print("📭 결과 폴더 없음")
    else:
        print("❌ playbooks 폴더 없음")
    
    print("=== 기존 분석 기록 스캔 완료 ===\n")

"""분석 실행 기록 목록을 로드 (개선된 버전)"""
def load_analysis_history():

    history = []
    # logs 폴더에서 ansible_execute_log_*.log 파일들 스캔
    if os.path.exists("logs"):
        log_files = glob.glob("logs/ansible_execute_log_*.log")
        print(f"📋 발견된 로그 파일 수: {len(log_files)}")
        
        for log_file in log_files:
            try:
                # 파일명에서 타임스탬프 추출
                filename = os.path.basename(log_file)
                timestamp_match = re.search(r'ansible_execute_log_(\d{8}_\d{6})\.log', filename)
                
                if timestamp_match:
                    timestamp = timestamp_match.group(1)
                    
                    # 해당하는 결과 폴더가 있는지 확인
                    result_folder = f"playbooks/playbook_result_{timestamp}"
                    
                    # 로그 파일이 있으면 기록에 추가 (결과 폴더가 없어도)
                    file_stat = os.stat(log_file)
                    file_size = file_stat.st_size
                    mtime = file_stat.st_mtime
                    execution_time = datetime.fromtimestamp(mtime)
                    
                    # 결과 폴더 및 JSON 파일 확인
                    has_results = False
                    json_count = 0
                    if os.path.exists(result_folder):
                        results_path = f"{result_folder}/results"
                        if os.path.exists(results_path):
                            json_files = glob.glob(f"{results_path}/*.json")
                            json_count = len(json_files)
                            has_results = json_count > 0
                    
                    record = {
                        'timestamp': timestamp,
                        'execution_time': execution_time,
                        'log_file': log_file,
                        'result_folder': result_folder,
                        'display_name': execution_time.strftime("%Y-%m-%d %H:%M:%S"),
                        'file_size': file_size,
                        'has_results': has_results,
                        'json_count': json_count,
                        'status': '완료' if has_results else '실패 (실행만)'
                    }
                    
                    history.append(record)
                    print(f"  ✅ {timestamp} - {record['status']} (JSON: {json_count}개)")
                    
                else:
                    print(f"  ❌ 타임스탬프 추출 실패: {filename}")
                    
            except Exception as e:
                print(f"  ❌ 파일 처리 오류 {log_file}: {str(e)}")
    else:
        print("📁 logs 폴더가 존재하지 않습니다.")
    
    # 최신 순으로 정렬
    history.sort(key=lambda x: x['execution_time'], reverse=True)
    return history

"""확장된 사이드바 렌더링 (개선된 버전)"""
def render_sidebar_with_history(vulnerability_categories=None, filename_mapping=None):
    
    # 설정 파일 상태 표시 (기존 코드)
    if vulnerability_categories and filename_mapping:
        st.sidebar.success("✅ 설정 파일 로드 완료")
    else:
        st.sidebar.error("❌ 설정 파일 로드 실패")
    
    # 분석 모듈 섹션
    st.sidebar.markdown("## 🔍 분석 모듈")
    
    # 정적 분석 (메인 페이지)로 이동 버튼
    if st.sidebar.button("📋 정적 분석 (KISA 가이드)", use_container_width=True):
        st.query_params.clear()  # 모든 쿼리 파라미터 제거해서 메인으로
        st.rerun()
    
    # 동적 분석 - 포트스캐닝 페이지로 이동 버튼
    if st.sidebar.button("🌐 포트 스캐닝 (nmap)", use_container_width=True):
        st.query_params.update({"page": "port_scanning"})
        st.rerun()
    
    # 동적 분석 - 웹 애플리케이션 테스트 페이지로 이동 버튼
    if st.sidebar.button("🕷️ 웹 애플리케이션 테스트", use_container_width=True):
        st.query_params.update({"page": "web_app_test"})
        st.rerun()
    
    st.sidebar.markdown("---")
                
    # 새로운 분석 기록 섹션
    st.sidebar.markdown("## 📊 분석 기록")
    
    # 기존 기록 디버깅 버튼 (개발 시에만)
    if st.sidebar.button("🔍 기존 기록 스캔 (새로고침)"):
        debug_existing_logs()
    
    # 분석 기록 로드
    analysis_history = load_analysis_history()
    
    if analysis_history:
        st.sidebar.markdown(f"**총 {len(analysis_history)}개의 실행 기록**")
        
        # 각 기록을 버튼으로 표시 (상태 포함)
        for i, record in enumerate(analysis_history):
            # 최근 10개만 표시
            if i >= 10:
                remaining = len(analysis_history) - 10
                st.sidebar.text(f"... 외 {remaining}개 더")
                break
            
            # 상태 아이콘 결정
            status_icon = "✅" if record['has_results'] else "❌"
            
            # 각 기록을 클릭 가능한 버튼으로 표시
            button_text = f"{status_icon} {record['display_name']}"
            button_help = f"상태: {record['status']}, JSON 결과: {record['json_count']}개"
            
            if st.sidebar.button(
                button_text, 
                key=f"history_{record['timestamp']}",
                help=button_help
            ):
                # 분석 리포트 페이지로 이동
                st.query_params.update({"report": record['timestamp']})
                st.rerun()
        
        st.sidebar.markdown("---")
        
        # # 기록 통계 표시
        # complete_records = sum(1 for r in analysis_history if r['has_results'])
        # incomplete_records = len(analysis_history) - complete_records
        
        # st.sidebar.markdown("**📈 기록 통계**")
        # st.sidebar.text(f"✅ 완료된 분석: {complete_records}개")
        # if incomplete_records > 0:
        #     st.sidebar.text(f"⏸️ 미완료: {incomplete_records}개")
        
    else:
        st.sidebar.info("아직 분석 기록이 없습니다.")
        st.sidebar.markdown("취약점 점검을 실행하면 기록이 표시됩니다.")

"""분석 리포트 표시 - analysis_report로 리다이렉션"""
def show_analysis_report(timestamp):

    # analysis_report 모듈 임포트
    try:
        import analysis_report
        
        # analysis_report의 main 함수 호출하면서 타임스탬프 전달
        analysis_report.main(timestamp)
        
    except ImportError:
        st.error("❌ analysis_report.py 모듈을 찾을 수 없습니다.")
        st.info("analysis_report.py 파일이 프로젝트 루트에 있는지 확인해주세요.")
        
        # 임시 대안: 기본 정보만 표시
        st.title("📊 분석 리포트")
        st.markdown(f"**실행 시간:** {timestamp}")
        
        if st.button("⬅️ 메인으로 돌아가기"):
            st.query_params.clear()
            st.rerun()
            
        st.info("상세 분석 리포트는 analysis_report.py 구현 후 제공됩니다.")
        
    except Exception as e:
        st.error(f"❌ analysis_report 모듈 로드 중 오류 발생: {str(e)}")
        
        if st.button("⬅️ 메인으로 돌아가기"):
            st.query_params.clear()
            st.rerun()