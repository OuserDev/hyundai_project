"""
분석 리포트 페이지 - 특정 실행 기록의 상세 분석 결과 표시
다종/다중 서버 환경에 최적화된 리팩토링 버전
"""
import streamlit as st
import os
import json
import pandas as pd
from datetime import datetime
import glob
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import base64

def load_timestamp_results(timestamp):
    """특정 타임스탬프의 JSON 결과 파일들을 로드"""
    result_folder = f"playbooks/playbook_result_{timestamp}/results"
    
    if not os.path.exists(result_folder):
        return None, f"결과 폴더를 찾을 수 없습니다: {result_folder}"
    
    json_files = glob.glob(f"{result_folder}/*.json")
    if not json_files:
        # JSON 파일이 없을 때 로그 파일 정보 추가 제공
        log_file = f"logs/ansible_execute_log_{timestamp}.log"
        error_msg = f"JSON 결과 파일을 찾을 수 없습니다: {result_folder}"
        
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    log_content = f.read()
                
                # 로그에서 오류 관련 정보 추출
                error_lines = []
                failed_lines = []
                recap_started = False
                
                for line in log_content.split('\n'):
                    line_lower = line.lower()
                    
                    if "play recap" in line_lower:
                        recap_started = True
                        continue
                    
                    if any(keyword in line_lower for keyword in ['error', 'failed', 'fatal', 'unreachable']):
                        if recap_started and "failed=" in line_lower:
                            failed_lines.append(line.strip())
                        elif not recap_started:
                            error_lines.append(line.strip())
                
                detailed_info = {
                    'error_msg': error_msg,
                    'log_file': log_file,
                    'has_log': True,
                    'error_lines': error_lines[-10:] if error_lines else [],
                    'failed_summary': failed_lines,
                    'log_size': len(log_content),
                }
                
                return None, detailed_info
                
            except Exception as e:
                error_msg += f"\n로그 파일 읽기 실패: {str(e)}"
        else:
            error_msg += f"\n관련 로그 파일도 찾을 수 없습니다: {log_file}"
        
        return None, error_msg
        
    all_data = []
    file_info = []
    server_list = set()
    check_types = set()
    
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                filename = os.path.basename(json_file)
                file_info.append({
                    'filename': filename,
                    'path': json_file,
                    'size': os.path.getsize(json_file),
                    'data_type': type(data).__name__
                })
                
                # 데이터 정규화 및 추가 정보 추출
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            server_list.add(item.get('hostname', 'Unknown'))
                            # 파일명에서 점검 타입 추출
                            check_type = filename.split('_')[1:3]  # 예: 1_1_1
                            if len(check_type) >= 2:
                                check_types.add('_'.join(check_type))
                    all_data.extend(data)
                elif isinstance(data, dict):
                    server_list.add(data.get('hostname', 'Unknown'))
                    check_type = filename.split('_')[1:3]
                    if len(check_type) >= 2:
                        check_types.add('_'.join(check_type))
                    all_data.append(data)
                    
        except Exception as e:
            st.error(f"❌ 파일 {json_file} 로드 실패: {str(e)}")
            continue
    
    return {
        'data': all_data,
        'file_info': file_info,
        'total_files': len(json_files),
        'loaded_files': len(file_info),
        'servers': list(server_list),
        'check_types': list(check_types)
    }, None

def create_vulnerability_severity_chart(df):
    """취약점 심각도별 차트 생성"""
    if df.empty:
        return None
        
    severity_counts = df.groupby(['전체 취약 여부', '진단 결과']).size().reset_index(name='count')
    
    fig = px.sunburst(
        severity_counts,
        path=['전체 취약 여부', '진단 결과'],
        values='count',
        title="취약점 심각도 분석",
        color='count',
        color_continuous_scale='RdYlGn_r'
    )
    return fig

def create_server_comparison_chart(df):
    """서버별 비교 차트"""
    if df.empty:
        return None
        
    server_stats = df.groupby('호스트').agg({
        '전체 취약 여부': ['count', 'sum'],
        '조치 여부': 'sum'
    }).round(2)
    
    server_stats.columns = ['총_점검', '취약_발견', '조치_완료']
    server_stats['양호'] = server_stats['총_점검'] - server_stats['취약_발견']
    server_stats = server_stats.reset_index()
    
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('서버별 취약점 현황', '조치 완료율', '취약점 분포', '서버 위험도'),
        specs=[[{"type": "bar"}, {"type": "bar"}],
               [{"type": "pie"}, {"type": "scatter"}]]
    )
    
    # 서버별 취약점 현황
    fig.add_trace(
        go.Bar(x=server_stats['호스트'], y=server_stats['양호'], name='양호', marker_color='green'),
        row=1, col=1
    )
    fig.add_trace(
        go.Bar(x=server_stats['호스트'], y=server_stats['취약_발견'], name='취약', marker_color='red'),
        row=1, col=1
    )
    
    # 조치 완료율
    server_stats['조치율'] = (server_stats['조치_완료'] / server_stats['취약_발견'].replace(0, 1) * 100).fillna(0)
    fig.add_trace(
        go.Bar(x=server_stats['호스트'], y=server_stats['조치율'], name='조치율(%)', marker_color='blue'),
        row=1, col=2
    )
    
    # 전체 취약점 분포
    total_vulnerable = server_stats['취약_발견'].sum()
    total_safe = server_stats['양호'].sum()
    fig.add_trace(
        go.Pie(labels=['양호', '취약'], values=[total_safe, total_vulnerable], name="전체분포"),
        row=2, col=1
    )
    
    # 서버 위험도 (취약점 수 vs 조치율)
    fig.add_trace(
        go.Scatter(
            x=server_stats['취약_발견'], 
            y=server_stats['조치율'],
            mode='markers+text',
            text=server_stats['호스트'],
            textposition="top center",
            marker=dict(size=server_stats['총_점검']*2, color='orange'),
            name='위험도'
        ),
        row=2, col=2
    )
    
    fig.update_layout(height=800, showlegend=True, title_text="서버별 종합 보안 분석")
    return fig

def create_vulnerability_details_analysis(df):
    """취약점 상세 분석"""
    if df.empty:
        return None, None
        
    # 취약점 유형별 분석
    vulnerable_data = df[df['전체 취약 여부'] == True]
    
    if vulnerable_data.empty:
        return None, None
    
    # 작업 설명별 취약점 분포
    task_vuln = vulnerable_data['작업 설명'].value_counts()
    
    fig1 = px.bar(
        x=task_vuln.values, 
        y=task_vuln.index,
        orientation='h',
        title="취약점 유형별 발견 건수",
        labels={'x': '발견 건수', 'y': '취약점 유형'},
        color=task_vuln.values,
        color_continuous_scale='Reds'
    )
    fig1.update_layout(height=400)
    
    # 조치 상태별 분석
    remediation_status = vulnerable_data.groupby(['조치 결과', '호스트']).size().reset_index(name='count')
    
    fig2 = px.bar(
        remediation_status,
        x='호스트',
        y='count',
        color='조치 결과',
        title="서버별 조치 상태",
        barmode='stack'
    )
    fig2.update_layout(height=400)
    
    return fig1, fig2

def create_detailed_file_analysis(df):
    """상세 파일 분석 (SUID/SGID, 소유자 없는 파일 등)"""
    if df.empty:
        return None
        
    # 취약 사유에서 파일 정보가 있는 항목들 추출
    file_vulns = []
    
    for _, row in df.iterrows():
        if row['전체 취약 여부'] and '취약 사유' in row and row['취약 사유']:
            reason = str(row['취약 사유'])
            if 'SUID' in reason or 'SGID' in reason or '소유자' in reason or '파일' in reason:
                file_vulns.append({
                    '서버': row['호스트'],
                    '점검항목': row['작업 설명'],
                    '사유': reason[:100] + '...' if len(reason) > 100 else reason,
                    '조치상태': row['조치 결과'] if row['조치 결과'] else '미조치'
                })
    
    if not file_vulns:
        return None
        
    file_df = pd.DataFrame(file_vulns)
    
    # 서버별 파일 취약점 현황
    fig = px.treemap(
        file_df,
        path=['서버', '점검항목', '조치상태'],
        title="서버별 파일 취약점 상세 현황",
        color='조치상태',
        color_discrete_map={
            '수동 조치 필요': 'red',
            '미조치': 'orange',
            '조치완료': 'green'
        }
    )
    fig.update_layout(height=500)
    
    return fig

def create_execution_timeline(timestamp):
    """실행 타임라인 분석"""
    log_file = f"logs/ansible_execute_log_{timestamp}.log"
    
    if not os.path.exists(log_file):
        return None
        
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            log_content = f.read()
        
        # 로그에서 시간 정보 추출
        timeline_events = []
        for line in log_content.split('\n'):
            if '[' in line and ']' in line:
                try:
                    time_part = line.split('[')[1].split(']')[0]
                    event_part = line.split(']')[1].strip()
                    
                    if 'TASK' in event_part or 'PLAY' in event_part:
                        timeline_events.append({
                            'time': time_part,
                            'event': event_part[:50] + '...' if len(event_part) > 50 else event_part,
                            'type': 'TASK' if 'TASK' in event_part else 'PLAY'
                        })
                except:
                    continue
        
        if timeline_events:
            timeline_df = pd.DataFrame(timeline_events)
            
            fig = px.timeline(
                timeline_df,
                x_start="time",
                x_end="time", 
                y="event",
                color="type",
                title="Ansible 실행 타임라인"
            )
            fig.update_layout(height=600)
            return fig
            
    except Exception as e:
        st.error(f"타임라인 생성 실패: {str(e)}")
    
    return None

def download_log_file(timestamp):
    """로그 파일 다운로드 함수"""
    log_file = f"logs/ansible_execute_log_{timestamp}.log"
    
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                log_content = f.read()
            
            return st.download_button(
                label="📥 실행 로그 다운로드",
                data=log_content,
                file_name=f"ansible_log_{timestamp}.log",
                mime="text/plain",
                key=f"download_log_{timestamp}"
            )
        except Exception as e:
            st.error(f"로그 파일 읽기 실패: {str(e)}")
            return None
    else:
        st.warning("로그 파일을 찾을 수 없습니다.")
        return None

def parse_single_result(data):
    """단일 결과 데이터 파싱 (개선된 버전)"""
    # vulnerability_details에서 추가 정보 추출
    vuln_details = data.get("vulnerability_details", {})
    vulnerable_files = []
    
    # 다양한 형태의 취약 파일 정보 추출
    if "vulnerable_files_found" in vuln_details:
        vulnerable_files = vuln_details["vulnerable_files_found"]
    elif "file_list" in vuln_details:
        vulnerable_files = vuln_details["file_list"]
    elif "vulnerable_files" in vuln_details:
        vulnerable_files = vuln_details["vulnerable_files"]
    
    return pd.DataFrame([{
        "호스트": data.get("hostname", "알 수 없음"),
        "진단 결과": data.get("diagnosis_result", "알 수 없음"),
        "전체 취약 여부": data.get("is_vulnerable", False),
        "조치 여부": data.get("remediation_applied", False),
        "조치 결과": data.get("remediation_result", ""),
        "조치 시간": data.get("remediation_timestamp", ""),
        "작업 설명": data.get("task_description", ""),
        "플레이북": data.get("playbook_name", ""),
        "취약 사유": vuln_details.get("reason", ""),
        "취약 파일 수": len(vulnerable_files) if vulnerable_files else 0,
        "권장사항": vuln_details.get("recommendation", ""),
        "현재 권한": vuln_details.get("current_mode", ""),
        "현재 소유자": vuln_details.get("current_owner", "")
    }])

def main(timestamp=None):
    """메인 분석 리포트 페이지"""
    
    if not timestamp:
        query_params = st.query_params
        timestamp = query_params.get("report", None)
    
    if not timestamp:
        st.error("❌ 분석 리포트를 선택해주세요.")
        st.stop()
    
    # 페이지 제목과 실행 시간
    col1, col2 = st.columns([3, 2])

    with col1:
        st.title("🔒 보안 점검 분석 대시보드")

    with col2:
        try:
            dt = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            st.markdown(f"<h4 style='text-align: right; margin-top: 20px; color: #1976d2;'>📅 {formatted_time}</h4>", 
                    unsafe_allow_html=True)
        except:
            st.markdown(f"<h4 style='text-align: right; margin-top: 20px; color: #1976d2;'>📅 {timestamp}</h4>", 
                    unsafe_allow_html=True)

    # 로그 다운로드 및 메인으로 돌아가기 버튼
    col1, col2, col3 = st.columns([1, 1, 3])

    with col1:
        download_log_file(timestamp)

    with col2:
        # 메인화면 돌아가기 버튼
        if st.button("⬅️ 메인화면 돌아가기"):
            st.query_params.clear()
            st.rerun()
    
    st.markdown("---")
        
    # 데이터 로드
    with st.spinner("📂 분석 결과 데이터 로딩 중..."):
        result_data, error = load_timestamp_results(timestamp)
        
        if error:
            if isinstance(error, dict):
                st.error(f"❌ {error['error_msg']}")
                
                if error.get('has_log'):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.info(f"📄 로그 파일: `{error['log_file']}`") 
                    with col2:
                        st.info(f"📊 로그 크기: {error['log_size']:,} bytes")
                    
                    if error.get('failed_summary'):
                        st.subheader("⚠️ 실행 실패 요약 (PLAY RECAP)")
                        for line in error['failed_summary']:
                            st.code(line)
                    
                    if error.get('error_lines'):
                        st.subheader("🚨 실행 중 발견된 오류들 (최근 10개)")
                        for line in error['error_lines']:
                            st.code(line, language="text")
                    
                    st.subheader("📋 전체 실행 로그")
                    try:
                        with open(error['log_file'], 'r', encoding='utf-8') as f:
                            full_log = f.read()
                        st.code(full_log, language="text")
                    except Exception as e:
                        st.error(f"로그 파일 읽기 실패: {str(e)}")
            else:
                st.error(f"❌ {error}")
            return            

        if not result_data or not result_data['data']:
            st.warning("📭 분석 결과 데이터가 없습니다.")
            return
    
    # 데이터 파싱
    try:
        all_dataframes = []
        
        for data_item in result_data['data']:
            if isinstance(data_item, dict):
                df = parse_single_result(data_item)
                all_dataframes.append(df)
        
        if not all_dataframes:
            st.warning("📭 파싱 가능한 데이터가 없습니다.")
            return
        
        df = pd.concat(all_dataframes, ignore_index=True)
        
        # 성공 메시지와 기본 통계
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.success(f"✅ **{len(df)}**개 점검 항목")
        with col2:
            st.info(f"🖥️ **{len(result_data['servers'])}**개 서버")
        with col3:
            st.warning(f"📁 **{result_data['total_files']}**개 결과 파일")
        with col4:
            vulnerable_count = df[df['전체 취약 여부'] == True].shape[0]
            if vulnerable_count > 0:
                st.error(f"⚠️ **{vulnerable_count}**개 취약점")
            else:
                st.success("🛡️ **취약점 없음**")
        
    except Exception as e:
        st.error(f"❌ 데이터 파싱 중 오류 발생: {str(e)}")
        return
    
    # 탭 구성
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📊 종합 대시보드", 
        "🖥️ 서버별 분석", 
        "🔍 취약점 상세", 
        "📁 파일 시스템 분석",
        "⏱️ 실행 분석", 
        "📄 원본 데이터"
    ])
    
    with tab1:
        # === 종합 대시보드 ===
        st.header("📋 보안 점검 종합 현황")
        
        # 핵심 메트릭
        total_checks = len(df)
        vulnerable_items = df[df['전체 취약 여부'] == True].shape[0] 
        safe_items = df[df['전체 취약 여부'] == False].shape[0]
        remediation_needed = df[df['조치 결과'].str.contains("수동 조치 필요", case=False, na=False)].shape[0]
        remediation_complete = df[df['조치 결과'].str.contains("완료|성공", case=False, na=False)].shape[0]
        
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("🔍 총 점검 항목", total_checks)
        col2.metric("⚠️ 취약점 발견", vulnerable_items, delta=f"{(vulnerable_items/total_checks*100):.1f}%")
        col3.metric("✅ 양호 항목", safe_items, delta=f"{(safe_items/total_checks*100):.1f}%")
        col4.metric("🔧 조치 필요", remediation_needed)
        col5.metric("🛡️ 조치 완료", remediation_complete)
        
        st.markdown(" ")
        
        # 종합 차트
        fig_vulnerability = create_vulnerability_severity_chart(df)
        if fig_vulnerability:
            st.plotly_chart(fig_vulnerability, use_container_width=True)
        
        # 서버 비교 차트
        fig_server_comparison = create_server_comparison_chart(df)
        if fig_server_comparison:
            st.plotly_chart(fig_server_comparison, use_container_width=True)
    
    with tab2:
        # === 서버별 분석 ===
        st.header("🖥️ 서버별 상세 분석")
        
        # 서버 선택
        selected_server = st.selectbox(
            "분석할 서버 선택:",
            options=['전체'] + result_data['servers'],
            index=0
        )
        
        if selected_server == '전체':
            server_df = df
        else:
            server_df = df[df['호스트'] == selected_server]
        
        if len(server_df) > 0:
            # 서버별 통계
            col1, col2= st.columns(2)
            
            with col1:
                st.subheader("📊 점검 현황")
                server_stats = server_df.groupby('호스트').agg({
                    '전체 취약 여부': ['count', 'sum']
                }).round(2)
                server_stats.columns = ['총점검', '취약발견']
                server_stats['양호'] = server_stats['총점검'] - server_stats['취약발견']
                st.dataframe(server_stats, use_container_width=True)
            
            with col2:
                st.subheader("🔧 조치 현황")
                remediation_stats = server_df.groupby('호스트')['조치 결과'].value_counts().unstack(fill_value=0)
                st.dataframe(remediation_stats, use_container_width=True)
            
            st.subheader("📋 점검 유형")
            task_stats = server_df['작업 설명'].value_counts().head(10)
            
            # 표 형태로 변환
            task_df = pd.DataFrame({
                '점검 항목': task_stats.index,
                '점검 횟수': task_stats.values
            })
            
            st.dataframe(task_df, use_container_width=True, hide_index=True)
            
            # 서버별 취약점 히트맵
            if len(result_data['servers']) > 1:
                st.subheader("🔥 서버-취약점 히트맵")
                heatmap_data = df.pivot_table(
                    index='작업 설명', 
                    columns='호스트', 
                    values='전체 취약 여부', 
                    aggfunc='sum',
                    fill_value=0
                )
                
                if not heatmap_data.empty:
                    fig_heatmap = px.imshow(
                        heatmap_data.values,
                        labels=dict(x="서버", y="점검 항목", color="취약점 수"),
                        x=heatmap_data.columns,
                        y=heatmap_data.index,
                        color_continuous_scale='Reds',
                        aspect="auto"
                    )
                    fig_heatmap.update_layout(height=600)
                    st.plotly_chart(fig_heatmap, use_container_width=True)
        else:
            st.info("선택한 서버의 데이터가 없습니다.")
    
    with tab3:
        # === 취약점 상세 ===
        st.header("🔍 취약점 상세 분석")
        
        vulnerable_df = df[df['전체 취약 여부'] == True]
        
        if len(vulnerable_df) > 0:
            st.subheader(f"⚠️ 발견된 취약점 ({len(vulnerable_df)}개)")
            
            # 취약점 상세 차트
            fig1, fig2 = create_vulnerability_details_analysis(df)
            if fig1:
                st.plotly_chart(fig1, use_container_width=True)
            if fig2:
                st.plotly_chart(fig2, use_container_width=True)
            
            # 취약점 상세 테이블
            st.subheader("📋 취약점 상세 목록")
            
            # 필터링 옵션
            col1, col2 = st.columns(2)
            with col1:
                filter_server = st.multiselect(
                    "서버 필터:", 
                    options=vulnerable_df['호스트'].unique(),
                    default=vulnerable_df['호스트'].unique()
                )
            with col2:
                filter_remediation = st.selectbox(
                    "조치 상태 필터:",
                    options=['전체', '수동 조치 필요', '조치 완료', '미조치'],
                    index=0
                )
            
            # 필터 적용
            filtered_vuln = vulnerable_df[vulnerable_df['호스트'].isin(filter_server)]
            if filter_remediation != '전체':
                filtered_vuln = filtered_vuln[filtered_vuln['조치 결과'].str.contains(filter_remediation, case=False, na=False)]
            
            # 상세 정보 표시
            for idx, row in filtered_vuln.iterrows():
                with st.expander(f"🚨 {row['호스트']} - {row['작업 설명']}", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**진단 결과:** {row['진단 결과']}")
                        st.write(f"**플레이북:** {row['플레이북']}")
                        st.write(f"**조치 상태:** {row['조치 결과']}")
                        if row['취약 파일 수'] > 0:
                            st.write(f"**영향받는 파일:** {row['취약 파일 수']}개")
                    
                    with col2:
                        if row['취약 사유']:
                            st.write("**취약 사유:**")
                            st.info(row['취약 사유'])
                        if row['권장사항']:
                            st.write("**권장사항:**")
                            st.success(row['권장사항'])
                    
                    # 추가 기술적 세부사항
                    if row['현재 권한'] or row['현재 소유자']:
                        st.markdown("**🔧 기술적 세부사항:**")
                        tech_details = []
                        if row['현재 권한']:
                            tech_details.append(f"현재 권한: `{row['현재 권한']}`")
                        if row['현재 소유자']:
                            tech_details.append(f"현재 소유자: `{row['현재 소유자']}`")
                        st.markdown(" | ".join(tech_details))
        else:
            st.success("🛡️ 취약점이 발견되지 않았습니다!")
    
    with tab4:
        # === 파일 시스템 분석 ===
        st.header("📁 파일 시스템 보안 분석")
        
        # 파일 관련 취약점 필터링
        file_related_df = df[df['작업 설명'].str.contains("파일|권한|소유자|SUID|SGID", case=False, na=False)]
        
        if len(file_related_df) > 0:
            # 파일 시스템 취약점 차트
            fig_file_analysis = create_detailed_file_analysis(df)
            if fig_file_analysis:
                st.plotly_chart(fig_file_analysis, use_container_width=True)
            
            # 파일 권한 관련 통계
            st.subheader("📊 파일 권한 점검 통계")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # 권한 관련 취약점 분포
                permission_issues = file_related_df.groupby('작업 설명')['전체 취약 여부'].sum().sort_values(ascending=False)
                if not permission_issues.empty:
                    st.bar_chart(permission_issues)
            
            with col2:
                # 서버별 파일 권한 문제
                server_file_issues = file_related_df.groupby('호스트')['전체 취약 여부'].sum().sort_values(ascending=False)
                if not server_file_issues.empty:
                    st.bar_chart(server_file_issues)
            
            # 상세 파일 권한 문제 목록
            st.subheader("🔍 파일 권한 문제 상세")
            
            vulnerable_files = file_related_df[file_related_df['전체 취약 여부'] == True]
            
            if len(vulnerable_files) > 0:
                # 테이블 형태로 표시
                display_columns = ['호스트', '작업 설명', '진단 결과', '조치 결과', '취약 파일 수']
                st.dataframe(
                    vulnerable_files[display_columns].style.format({'취약 파일 수': '{:.0f}'}),
                    use_container_width=True
                )
                
                # 파일별 상세 정보
                with st.expander("📋 파일별 상세 정보 보기"):
                    for idx, row in vulnerable_files.iterrows():
                        if row['취약 파일 수'] > 0:
                            st.markdown(f"**{row['호스트']} - {row['작업 설명']}**")
                            st.markdown(f"- 취약 파일 수: {row['취약 파일 수']}개")
                            if row['취약 사유']:
                                st.markdown(f"- 상세 사유: {row['취약 사유'][:200]}...")
                            st.markdown("---")
            else:
                st.info("파일 권한 관련 취약점이 발견되지 않았습니다.")
        else:
            st.info("파일 시스템 관련 점검 항목이 없습니다.")
    
    with tab5:
        # === 실행 분석 ===
        st.header("⏱️ Ansible 실행 분석")
        
        # 실행 타임라인
        fig_timeline = create_execution_timeline(timestamp)
        if fig_timeline:
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.info("실행 타임라인 데이터를 생성할 수 없습니다.")
        
        # 실행 통계
        st.subheader("📊 실행 통계")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("전체 실행 시간", "계산 중...")  # 실제로는 로그에서 추출
            st.metric("평균 서버당 소요시간", f"{len(df) / len(result_data['servers']) if result_data['servers'] else 0:.1f}개 점검/서버")
        
        with col2:
            success_rate = (len(df[df['전체 취약 여부'] == False]) / len(df) * 100) if len(df) > 0 else 0
            st.metric("점검 성공률", f"{success_rate:.1f}%")
            
            automation_rate = (len(df[df['조치 결과'].str.contains("완료", case=False, na=False)]) / len(df) * 100) if len(df) > 0 else 0
            st.metric("자동 조치율", f"{automation_rate:.1f}%")
        
        with col3:
            st.metric("점검된 서버 수", len(result_data['servers']))
            st.metric("점검 항목 유형", len(result_data['check_types']))
        
        # 실행 로그 요약
        st.subheader("📋 실행 로그 요약")
        
        log_file = f"logs/ansible_execute_log_{timestamp}.log"
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    log_content = f.read()
                
                # 로그 통계 추출
                total_lines = len(log_content.split('\n'))
                error_count = log_content.lower().count('error')
                warning_count = log_content.lower().count('warning')
                success_count = log_content.lower().count('success')
                
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("총 로그 라인", total_lines)
                col2.metric("성공 메시지", success_count)
                col3.metric("경고 메시지", warning_count)
                col4.metric("오류 메시지", error_count)
                
                # 로그 미리보기 (마지막 20줄)
                log_lines = log_content.split('\n')
                preview_lines = log_lines[-20:] if len(log_lines) > 20 else log_lines
                
                with st.expander("📄 로그 미리보기 (마지막 20줄)"):
                    st.code('\n'.join(preview_lines), language="text")
                    
            except Exception as e:
                st.error(f"로그 파일 읽기 실패: {str(e)}")
        else:
            st.warning("로그 파일을 찾을 수 없습니다.")
    
    with tab6:
        # === 원본 데이터 ===
        st.header("📄 원본 데이터 및 다운로드")
        
        # 파일 정보 표시
        st.subheader("📂 로드된 파일 정보")
        
        if result_data['file_info']:
            file_info_df = pd.DataFrame(result_data['file_info'])
            
            # 파일 크기를 읽기 쉽게 변환
            def format_file_size(size_bytes):
                if size_bytes < 1024:
                    return f"{size_bytes} B"
                elif size_bytes < 1024**2:
                    return f"{size_bytes/1024:.1f} KB"
                else:
                    return f"{size_bytes/(1024**2):.1f} MB"
            
            file_info_df['readable_size'] = file_info_df['size'].apply(format_file_size)
            
            # 표시할 컬럼 선택
            display_file_info = file_info_df[['filename', 'readable_size', 'data_type']].copy()
            display_file_info.columns = ['파일명', '크기', '데이터 타입']
            
            st.dataframe(display_file_info, use_container_width=True)
        else:
            st.info("파일 정보가 없습니다.")
        
        # 데이터 요약 통계
        st.subheader("📊 데이터 요약")
        col1, col2, col3, col4 = st.columns(4)
        
        col1.metric("총 데이터 항목", len(df))
        col2.metric("처리된 서버", len(result_data['servers']))
        col3.metric("점검 유형", len(result_data['check_types']))
        col4.metric("결과 파일", result_data['total_files'])
        
        # 전체 데이터 테이블
        st.subheader("🔍 세부 데이터 보기")
        
        # 컬럼 선택 기능
        available_columns = df.columns.tolist()
        selected_columns = st.multiselect(
            "표시할 컬럼 선택:",
            options=available_columns,
            default=['호스트', '작업 설명', '진단 결과', '전체 취약 여부', '조치 결과']
        )
        
        if selected_columns:
            # 필터링 옵션
            col1, col2 = st.columns(2)
            
            with col1:
                show_only_vulnerable = st.checkbox("취약점만 표시", value=False)
            
            with col2:
                show_only_manual = st.checkbox("수동 조치 필요 항목만 표시", value=False)
            
            # 필터 적용
            filtered_df = df.copy()
            
            if show_only_vulnerable:
                filtered_df = filtered_df[filtered_df['전체 취약 여부'] == True]
            
            if show_only_manual:
                filtered_df = filtered_df[filtered_df['조치 결과'].str.contains("수동", case=False, na=False)]
            
            # 데이터 표시
            if len(filtered_df) > 0:
                st.dataframe(filtered_df[selected_columns], use_container_width=True)
                
                # 수동 조치 필요 항목 강조 표시
                manual_items = filtered_df[filtered_df['조치 결과'].str.contains("수동 조치 필요", case=False, na=False)]
                if len(manual_items) > 0:
                    st.warning(f"🔧 **수동 조치 필요 항목: {len(manual_items)}개**")
                    
                    with st.expander("🚨 수동 조치 필요 항목 상세보기"):
                        for idx, row in manual_items.iterrows():
                            st.markdown(f"**{row['호스트']}** - {row['작업 설명']}")
                            if row['취약 사유']:
                                st.markdown(f"- 사유: {row['취약 사유']}")
                            if row['권장사항']:
                                st.markdown(f"- 권장사항: {row['권장사항']}")
                            st.markdown("---")
            else:
                st.info("필터 조건에 맞는 데이터가 없습니다.")
        else:
            st.info("표시할 컬럼을 선택해주세요.")
        
        # 다운로드 섹션
        st.subheader("⬇️ 데이터 다운로드")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # CSV 다운로드
            csv = df.to_csv(index=False, encoding='utf-8-sig')
            st.download_button(
                "📊 전체 데이터 CSV 다운로드", 
                csv, 
                f"security_analysis_{timestamp}.csv", 
                "text/csv"
            )
        
        with col2:
            # 취약점만 CSV 다운로드
            vulnerable_only = df[df['전체 취약 여부'] == True]
            if len(vulnerable_only) > 0:
                vulnerable_csv = vulnerable_only.to_csv(index=False, encoding='utf-8-sig')
                st.download_button(
                    "⚠️ 취약점만 CSV 다운로드",
                    vulnerable_csv,
                    f"vulnerabilities_{timestamp}.csv",
                    "text/csv"
                )
            else:
                st.button("⚠️ 취약점만 CSV 다운로드", disabled=True, help="취약점이 없습니다")
        
        with col3:
            # JSON 원본 데이터 다운로드
            if result_data['data']:
                json_data = json.dumps(result_data['data'], ensure_ascii=False, indent=2)
                st.download_button(
                    "📋 원본 JSON 다운로드",
                    json_data,
                    f"raw_data_{timestamp}.json",
                    "application/json"
                )
        
        # 로그 파일 내용 표시
        st.subheader("📋 실행 로그 전체보기")
        log_file = f"logs/ansible_execute_log_{timestamp}.log"
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    log_content = f.read()
                
                # 로그 검색 기능
                search_term = st.text_input("🔍 로그 검색:", placeholder="검색할 키워드를 입력하세요")
                
                if search_term:
                    # 검색 결과 하이라이팅
                    highlighted_content = log_content.replace(search_term, f"**{search_term}**")
                    matching_lines = [line for line in log_content.split('\n') if search_term.lower() in line.lower()]
                    
                    st.info(f"검색 결과: {len(matching_lines)}개 라인에서 '{search_term}' 발견")
                    
                    if matching_lines:
                        st.markdown("**검색 결과 미리보기 (최대 10개):**")
                        for line in matching_lines[:10]:
                            st.code(line.strip())
                
                # 전체 로그 표시
                st.code(log_content, language="text")
                
            except Exception as e:
                st.error(f"로그 파일 읽기 실패: {str(e)}")
        else:
            st.warning(f"로그 파일을 찾을 수 없습니다: {log_file}")

if __name__ == "__main__":
    main()