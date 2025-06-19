"""
분석 리포트 페이지 - 특정 실행 기록의 상세 분석 결과 표시
Report.py 스타일 기반으로 구현
"""
import streamlit as st
import os
import json
import pandas as pd
from datetime import datetime
import glob
import plotly.express as px
import plotly.graph_objects as go

def load_timestamp_results(timestamp):
    """특정 타임스탬프의 JSON 결과 파일들을 로드"""
    result_folder = f"playbooks/playbook_result_{timestamp}/results"
    
    if not os.path.exists(result_folder):
        return None, f"결과 폴더를 찾을 수 없습니다: {result_folder}"
    
    json_files = glob.glob(f"{result_folder}/*.json")
    if not json_files:
        return None, f"JSON 결과 파일을 찾을 수 없습니다: {result_folder}"
    
    all_data = []
    file_info = []
    
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # 파일명에서 정보 추출
                filename = os.path.basename(json_file)
                file_info.append({
                    'filename': filename,
                    'path': json_file,
                    'size': os.path.getsize(json_file),
                    'data_type': type(data).__name__
                })
                
                # 데이터 정규화
                if isinstance(data, list):
                    all_data.extend(data)
                elif isinstance(data, dict):
                    all_data.append(data)
                    
        except Exception as e:
            st.error(f"❌ 파일 {json_file} 로드 실패: {str(e)}")
            continue
    
    return {
        'data': all_data,
        'file_info': file_info,
        'total_files': len(json_files),
        'loaded_files': len(file_info)
    }, None

def parse_single_result(data):
    """단일 결과 데이터 파싱"""
    return pd.DataFrame([{
        "호스트": data.get("hostname", "알 수 없음"),
        "진단 결과": data.get("diagnosis_result", "알 수 없음"),
        "전체 취약 여부": data.get("is_vulnerable", False),
        "조치 여부": data.get("remediation_applied", False),
        "조치 결과": data.get("remediation_result", ""),
        "조치 시간": data.get("remediation_timestamp", ""),
        "작업 설명": data.get("task_description", ""),
        "취약 사유": data.get("vulnerability_details", {}).get("ssh_reason", "")
    }])

def parse_multiple_results(data_list):
    """다중 결과 데이터 파싱"""
    rows = []
    for data in data_list:
        rows.append({
            "호스트": data.get("hostname", "알 수 없음"),
            "진단 결과": data.get("diagnosis_result", "알 수 없음"),
            "전체 취약 여부": data.get("is_vulnerable", False),
            "조치 여부": data.get("remediation_applied", False),
            "조치 결과": data.get("remediation_result", ""),
            "조치 시간": data.get("remediation_timestamp", ""),
            "작업 설명": data.get("task_description", ""),
            "취약 사유": data.get("vulnerability_details", {}).get("ssh_reason", "")
        })
    return pd.DataFrame(rows)

def main(timestamp=None):
    """메인 분석 리포트 페이지"""
    
    # 타임스탬프가 전달되지 않은 경우 URL 파라미터에서 추출
    if not timestamp:
        query_params = st.query_params
        timestamp = query_params.get("report", None)
    
    if not timestamp:
        st.error("❌ 분석 리포트를 선택해주세요.")
        st.stop()
    
    # 페이지 제목 및 네비게이션
    st.title("🔒 보안 진단 결과 대시보드")
    
    # 뒤로가기 버튼과 실행 정보
    col1, col2 = st.columns([1, 4])
    with col1:
        if st.button("⬅️ 메인으로 돌아가기"):
            st.query_params.clear()
            st.rerun()
    
    with col2:
        # 타임스탬프를 읽기 쉬운 형식으로 변환
        try:
            dt = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
            formatted_time = dt.strftime("%Y년 %m월 %d일 %H시 %M분 %S초")
            st.markdown(f"**📅 실행 시간:** {formatted_time}")
        except:
            st.markdown(f"**📅 실행 시간:** {timestamp}")
    
    # 데이터 로드
    with st.spinner("📂 분석 결과 데이터 로딩 중..."):
        result_data, error = load_timestamp_results(timestamp)
        
        if error:
            st.error(f"❌ {error}")
            return
            
        if not result_data or not result_data['data']:
            st.warning("📭 분석 결과 데이터가 없습니다.")
            return
    
    # 데이터 파싱
    try:
        all_dataframes = []
        
        # 각 데이터 항목을 DataFrame으로 변환
        for data_item in result_data['data']:
            if isinstance(data_item, dict):
                df = parse_single_result(data_item)
                all_dataframes.append(df)
        
        if not all_dataframes:
            st.warning("📭 파싱 가능한 데이터가 없습니다.")
            return
        
        # 모든 DataFrame 결합
        df = pd.concat(all_dataframes, ignore_index=True)
        
        st.success(f"✅ 분석 결과 로드 완료 ({len(df)}개 항목, {result_data['total_files']}개 파일)")
        
    except Exception as e:
        st.error(f"❌ 데이터 파싱 중 오류 발생: {str(e)}")
        return
    
    # 탭 구성
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 대시보드", 
        "🖥️ 서버별 결과", 
        "🔍 취약점 상세", 
        "📈 트렌드 분석", 
        "📄 원본 데이터"
    ])
    
    with tab1:
        # === 대시보드 탭 ===
        st.header("📋 요약 통계")
        
        # 메트릭 표시
        col1, col2, col3, col4, col5 = st.columns(5)
        
        total_hosts = len(df)
        vulnerable_hosts = df[df["전체 취약 여부"] == True].shape[0] 
        safe_hosts = df[df["전체 취약 여부"] == False].shape[0]
        
        # 조치 결과 분석
        mitigation_success = df["조치 결과"].str.contains("성공|완료|ok|OK|Success", case=False, na=False).sum()
        mitigation_failed = df["조치 결과"].str.contains("실패|fail|error", case=False, na=False).sum()
        
        col1.metric("총 호스트 수", total_hosts)
        col2.metric("취약 호스트 수", vulnerable_hosts)
        col3.metric("양호 호스트 수", safe_hosts)
        col4.metric("🛠️ 조치 완료", mitigation_success)
        col5.metric("⚠️ 조치 실패", mitigation_failed)
        
        st.markdown(" ")
        
        # 요약 차트
        summary_data = pd.DataFrame({
            "항목": ["총 호스트 수", "취약 호스트 수", "양호 호스트 수", "조치 완료", "조치 실패"],
            "개수": [total_hosts, vulnerable_hosts, safe_hosts, mitigation_success, mitigation_failed]
        })
        
        color_map = {
            "총 호스트 수": "#A9A9A9",   # 회색
            "취약 호스트 수": "#FF0000", # 빨강
            "양호 호스트 수": "#0000FF", # 파랑
            "조치 완료": "#00BFFF",      # 하늘색
            "조치 실패": "#FF8C00"       # 주황색
        }
        
        fig_summary = px.bar(summary_data,
                             x="항목",
                             y="개수", 
                             color="항목",
                             text="개수",
                             color_discrete_map=color_map,
                             title="보안 진단 요약")
        fig_summary.update_layout(showlegend=False)
        st.plotly_chart(fig_summary, use_container_width=True)
        
        st.markdown("---")
        
        # 조치 이력 타임라인
        st.subheader("🕒 조치 이력 타임라인")
        try:
            df_timeline = df.copy()
            df_timeline["조치 시간"] = pd.to_datetime(df_timeline["조치 시간"], errors='coerce')
            timeline = df_timeline[df_timeline["조치 시간"].notnull()].sort_values("조치 시간")
            
            if len(timeline) > 0:
                fig_timeline = px.scatter(timeline, 
                                        x="조치 시간", 
                                        y="호스트", 
                                        color="조치 결과",
                                        title="조치 시간별 조치 내역", 
                                        symbol="조치 결과")
                st.plotly_chart(fig_timeline, use_container_width=True)
            else:
                st.info("조치 시간 데이터가 없어 타임라인을 표시할 수 없습니다.")
        except Exception as e:
            st.info(f"조치 시간 형식 오류로 타임라인을 표시할 수 없습니다: {str(e)}")
    
    with tab2:
        # === 서버별 결과 탭 ===
        st.header("🖥️ 서버별 점검 결과")
        
        # 호스트별 그룹화
        if len(df) > 0:
            host_summary = df.groupby('호스트').agg({
                '전체 취약 여부': ['count', 'sum'],
                '조치 여부': 'sum'
            }).round(2)
            
            st.dataframe(host_summary, use_container_width=True)
            
            # 호스트별 취약점 분포 차트
            host_vuln = df.groupby(['호스트', '전체 취약 여부']).size().reset_index(name='count')
            fig_host = px.bar(host_vuln, x='호스트', y='count', color='전체 취약 여부',
                             title="호스트별 취약점 분포")
            st.plotly_chart(fig_host, use_container_width=True)
        else:
            st.info("표시할 데이터가 없습니다.")
    
    with tab3:
        # === 취약점 상세 탭 ===
        st.header("🔍 취약점 상세 분석")
        
        if len(df) > 0:
            # 진단 결과별 분류
            diagnosis_summary = df['진단 결과'].value_counts()
            st.subheader("진단 결과 분포")
            fig_diagnosis = px.pie(values=diagnosis_summary.values, 
                                  names=diagnosis_summary.index,
                                  title="진단 결과별 분포")
            st.plotly_chart(fig_diagnosis, use_container_width=True)
            
            # 취약 사유 분석
            if '취약 사유' in df.columns:
                st.subheader("취약 사유 분석")
                vuln_reasons = df[df['취약 사유'] != '']['취약 사유'].value_counts()
                if len(vuln_reasons) > 0:
                    st.bar_chart(vuln_reasons)
                else:
                    st.info("취약 사유 데이터가 없습니다.")
        else:
            st.info("표시할 데이터가 없습니다.")
    
    with tab4:
        # === 트렌드 분석 탭 ===
        st.header("📈 트렌드 분석")
        st.info("🚧 추후 확장 예정: 이전 실행 결과와의 비교 분석")
        
        # 현재 데이터 기반 간단한 분석
        if len(df) > 0:
            st.subheader("현재 실행 결과 분석")
            
            if total_hosts > 0:
                vulnerability_rate = (vulnerable_hosts / total_hosts) * 100
                safety_rate = (safe_hosts / total_hosts) * 100
                
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("취약점 발견율", f"{vulnerability_rate:.1f}%")
                with col2:
                    st.metric("보안 준수율", f"{safety_rate:.1f}%")
    
    with tab5:
        # === 원본 데이터 탭 ===
        st.header("📄 원본 데이터")
        
        # 파일 정보 표시
        st.subheader("📂 로드된 파일 정보")
        file_info_df = pd.DataFrame(result_data['file_info'])
        st.dataframe(file_info_df, use_container_width=True)
        
        # 전체 데이터 테이블
        st.subheader("🔍 세부 데이터 보기")
        st.dataframe(df, use_container_width=True)
        
        # CSV 다운로드
        csv = df.to_csv(index=False, encoding='utf-8-sig')
        st.download_button(
            "⬇️ CSV 다운로드", 
            csv, 
            f"security_report_{timestamp}.csv", 
            "text/csv"
        )
        
        # 로그 파일 내용 표시
        st.subheader("📋 실행 로그")
        log_file = f"logs/ansible_execute_log_{timestamp}.log"
        if os.path.exists(log_file):
            if st.checkbox("로그 파일 내용 보기"):
                try:
                    with open(log_file, 'r', encoding='utf-8') as f:
                        log_content = f.read()
                    st.code(log_content, language="text")
                except Exception as e:
                    st.error(f"로그 파일 읽기 실패: {str(e)}")
        else:
            st.warning(f"로그 파일을 찾을 수 없습니다: {log_file}")

if __name__ == "__main__":
    main()