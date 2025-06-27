"""
분석 리포트 페이지 - 특정 실행 기록의 상세 분석 결과 표시
다종/다중 서버 환경에 최적화된 리팩토링 버전 (실질적 상태 반영)
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

def create_security_improvement_analysis(df):
    """보안 개선 효과 분석 (ignore 항목 반영)"""
    if df.empty:
        return None, None, None
        
    # 실질적 상태가 없으면 생성 (ignore 고려)
    if '실질적_양호상태' not in df.columns:
        df['실질적_양호상태'] = (
            (df['전체 취약 여부'] == False) | 
            (df['조치 결과'].str.contains("조치 완료|완료|성공", case=False, na=False))
        )
    
    # 1. 원래부터 양호 (조치 불필요)
    originally_safe = df[
        (df['실질적_양호상태'] == True) & 
        (df['조치 여부'] == False)
    ]
    
    # 2. 조치 후 양호 (취약 발견 → 조치 완료)
    remediated_safe = df[
        (df['조치 여부'] == True) & 
        (df['조치 결과'].str.contains("조치 완료|완료|성공", case=False, na=False))
    ]
    
    # 3. 조치 시도했지만 실패/무시됨
    attempted_but_failed = df[
        (df['조치 여부'] == True) & 
        (df['조치 결과'].str.contains("실패|오류|ERROR|FAILED|무시|ignore|건너뛰|skip", case=False, na=False))
    ]
    
    # 4. 여전히 취약 (조치 안됨)
    still_vulnerable = df[
        (df['실질적_양호상태'] == False) & 
        (df['조치 여부'] == False)
    ]
    
    # 통계 데이터 생성 (4개 카테고리)
    improvement_stats = pd.DataFrame({
        '항목': ['원래부터 양호', '조치 후 양호', '조치 시도(실패/무시)', '여전히 취약'],
        '개수': [len(originally_safe), len(remediated_safe), len(attempted_but_failed), len(still_vulnerable)],
        '비율(%)': [
            len(originally_safe) / len(df) * 100,
            len(remediated_safe) / len(df) * 100,
            len(attempted_but_failed) / len(df) * 100,
            len(still_vulnerable) / len(df) * 100
        ]
    })
    
    # 파이 차트 생성 (4개 카테고리)
    fig1 = px.pie(
        improvement_stats,
        values='개수',
        names='항목',
        title="보안 상태 분포 (조치 시도 포함)",
        color='항목',  # 🔧 이 라인 추가
        color_discrete_map={
            '원래부터 양호': '#28a745',        # 녹색
            '조치 후 양호': '#17a2b8',         # 청록색  
            '조치 시도(실패/무시)': '#ffc107', # 노란색
            '여전히 취약': '#dc3545'           # 빨간색
        }
    )
    
    # 서버별 개선 효과 차트 (4개 카테고리)
    server_improvement = df.groupby('호스트').apply(lambda x: pd.Series({
        '원래_양호': len(x[(x['실질적_양호상태'] == True) & (x['조치 여부'] == False)]),
        '조치_후_양호': len(x[(x['조치 여부'] == True) & 
                            (x['조치 결과'].str.contains("조치 완료|완료|성공", case=False, na=False))]),
        '조치_시도_실패': len(x[(x['조치 여부'] == True) & 
                             (x['조치 결과'].str.contains("실패|오류|ERROR|FAILED|무시|ignore|건너뛰|skip", case=False, na=False))]),
        '여전히_취약': len(x[(x['실질적_양호상태'] == False) & (x['조치 여부'] == False)])
    })).reset_index()
    
    fig2 = px.bar(
        server_improvement,
        x='호스트',
        y=['원래_양호', '조치_후_양호', '조치_시도_실패', '여전히_취약'],
        title="서버별 보안 개선 효과 (조치 시도 포함)",
        labels={'value': '항목 수', 'variable': '상태'},
        color_discrete_map={
            '원래_양호': '#28a745',
            '조치_후_양고': '#17a2b8', 
            '조치_시도_실패': '#ffc107',
            '여전히_취약': '#dc3545'
        }
    )
    fig2.update_layout(height=400)
    
    return fig1, fig2, {
        'originally_safe': originally_safe,
        'remediated_safe': remediated_safe,
        'attempted_but_failed': attempted_but_failed,
        'still_vulnerable': still_vulnerable,
        'stats': improvement_stats
    }
    
def create_failure_analysis(df):
    """실패한 작업들에 대한 상세 분석 (ignore 포함)"""
    if df.empty:
        return None, None, None
    
    # ignore된 항목들과 실패한 항목들 모두 포함
    failed_items = df[
        (df['조치 여부'] == True) & 
        (df['조치 결과'].str.contains("실패|오류|ERROR|FAILED|무시|ignore|건너뛰|skip", case=False, na=False))
    ]
    
    if len(failed_items) == 0:
        return None, None, {"message": "실패하거나 무시된 작업이 없습니다."}
    
    # 실패 유형 재분류
    def categorize_failure_type(result):
        result_lower = str(result).lower()
        if any(word in result_lower for word in ['무시', 'ignore', 'ignored']):
            return 'Ignored (무시됨)'
        elif any(word in result_lower for word in ['건너뛰', 'skip', 'skipped']):
            return 'Skipped (건너뜀)'
        elif any(word in result_lower for word in ['실패', 'failed', 'error']):
            return 'Failed (실패)'
        else:
            return 'Other (기타)'
    
    failed_items_copy = failed_items.copy()
    failed_items_copy['실패_유형'] = failed_items_copy['조치 결과'].apply(categorize_failure_type)
    
    # 1. 실패 유형별 분류
    failure_types = failed_items_copy.groupby('실패_유형').size().reset_index(name='count')
    
    fig1 = px.pie(
        failure_types,
        values='count',
        names='실패_유형',
        title="실행 문제 유형별 분포 (실패/무시/건너뜀)",
        color_discrete_map={
            'Failed (실패)': '#ff4444',
            'Ignored (무시됨)': '#ff8800', 
            'Skipped (건너뜀)': '#ffcc00',
            'Other (기타)': '#888888'
        }
    )
        
    # 2. 서버별 실패 현황
    server_failures = failed_items.groupby('호스트').agg({
        '작업 설명': 'count',
        '조치 결과': lambda x: list(x.unique())
    }).reset_index()
    server_failures.columns = ['서버명', '실패_개수', '실패_유형들']
    
    fig2 = px.bar(
        server_failures,
        x='서버명',
        y='실패_개수',
        title="서버별 실패한 작업 수",
        color='실패_개수',
        color_continuous_scale='Reds'
    )
    fig2.update_layout(height=400)
    
    # 3. 실패 상세 데이터
    failure_details = {
        'total_failures': len(failed_items),
        'affected_servers': len(failed_items['호스트'].unique()),
        'failure_types': failure_types.to_dict('records'),
        'server_breakdown': server_failures.to_dict('records'),
        'detailed_failures': failed_items[['호스트', '작업 설명', '조치 결과', '취약 사유']].to_dict('records')
    }
    
    return fig1, fig2, failure_details

def create_unreachable_hosts_analysis(df, result_data):
    """접근 불가능한 호스트 분석"""
    # 모든 서버 vs 실제 결과가 있는 서버 비교
    expected_servers = set(result_data.get('servers', []))
    actual_servers = set(df['호스트'].unique()) if not df.empty else set()
    
    unreachable_servers = expected_servers - actual_servers
    
    if not unreachable_servers:
        return None, {"message": "모든 서버가 정상적으로 접근 가능합니다."}
    
    unreachable_data = pd.DataFrame({
        '서버명': list(unreachable_servers),
        '상태': ['접근 불가'] * len(unreachable_servers)
    })
    
    fig = px.bar(
        unreachable_data,
        x='서버명',
        y=[1] * len(unreachable_servers),
        title="접근 불가능한 서버 목록",
        color_discrete_sequence=['#ff4444']
    )
    fig.update_layout(
        height=300,
        yaxis_title="서버 수",
        showlegend=False
    )
    
    analysis_data = {
        'total_unreachable': len(unreachable_servers),
        'unreachable_servers': list(unreachable_servers),
        'reachable_servers': list(actual_servers),
        'success_rate': len(actual_servers) / len(expected_servers) * 100 if expected_servers else 0
    }
    
    return fig, analysis_data

def create_vulnerability_severity_chart(df):
    """취약점 심각도별 차트 생성 (실질적 상태 반영, 조치 후 양호 구분)"""
    if df.empty:
        return None
    
    # 실질적 상태가 없으면 생성
    if '실질적_양호상태' not in df.columns:
        df['실질적_양호상태'] = (
            (df['전체 취약 여부'] == False) | 
            (df['조치 결과'].str.contains("조치 완료|완료|성공", case=False, na=False))
        )
    
    # 3단계 상태로 재분류
    df_chart = df.copy()
    
    def categorize_status(row):
        if row['실질적_양호상태'] == False:
            return '실질적 취약'
        elif row['조치 여부'] == True and '조치 완료' in str(row['조치 결과']):
            return '조치 후 양호'
        else:
            return '원래부터 양호'
    
    df_chart['상세_상태'] = df_chart.apply(categorize_status, axis=1)
    
    severity_counts = df_chart.groupby(['상세_상태', '진단 결과']).size().reset_index(name='count')
    
    # 색상 매핑
    color_map = {
        '원래부터 양호': '#28a745',    # 녹색
        '조치 후 양호': '#17a2b8',     # 청록색
        '실질적 취약': '#dc3545'       # 빨간색
    }
    
    fig = px.sunburst(
        severity_counts,
        path=['상세_상태', '진단 결과'],
        values='count',
        title="취약점 심각도 분석 (조치 효과 구분)",
        color='상세_상태',
        color_discrete_map=color_map
    )
    return fig

def create_server_comparison_chart(df):
    """서버별 비교 차트 (실질적 상태 반영)"""
    if df.empty:
        return None
    
    # 실질적 상태가 없으면 생성
    if '실질적_양호상태' not in df.columns:
        df['실질적_양호상태'] = (
            (df['전체 취약 여부'] == False) | 
            (df['조치 결과'].str.contains("조치 완료|완료|성공", case=False, na=False))
        )
        
    # 실질적 상태 기준으로 서버별 통계 계산
    server_stats = df.groupby('호스트').agg({
        '실질적_양호상태': ['count', lambda x: (~x).sum()],  # 전체 개수, 실질적 취약 개수
        '조치 여부': 'sum'
    }).round(2)
    
    server_stats.columns = ['총_점검', '실질적_취약', '조치_완료']
    server_stats['실질적_양호'] = server_stats['총_점검'] - server_stats['실질적_취약']
    server_stats = server_stats.reset_index()
    
    # 세부 분류 추가
    server_details = df.groupby('호스트').apply(lambda x: pd.Series({
        '원래_양호': len(x[(x['실질적_양호상태'] == True) & (x['조치 여부'] == False)]),
        '조치_후_양호': len(x[(x['조치 여부'] == True) & 
                            (x['조치 결과'].str.contains("조치 완료|완료|성공", case=False, na=False))]),
        '여전히_취약': len(x[x['실질적_양호상태'] == False])
    })).reset_index()
    
    # 서버 통계와 세부 분류 병합
    server_stats = server_stats.merge(server_details, on='호스트')
    
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('서버별 실질적 취약점 현황', '조치 완료율', '전체 보안 상태 분포', '보안 개선 효과'),
        specs=[[{"type": "bar"}, {"type": "bar"}],
               [{"type": "pie"}, {"type": "bar"}]]
    )
    
    # 서버별 실질적 취약점 현황
    fig.add_trace(
        go.Bar(x=server_stats['호스트'], y=server_stats['실질적_양호'], name='실질적 양호', marker_color='green'),
        row=1, col=1
    )
    fig.add_trace(
        go.Bar(x=server_stats['호스트'], y=server_stats['실질적_취약'], name='실질적 취약', marker_color='red'),
        row=1, col=1
    )
    
    # 조치 완료율 (전체 점검 대비 조치 완료된 비율)
    # remediated_safe 계산
    remediated_safe = df[(df['조치 여부'] == True) & 
                        (df['조치 결과'].str.contains("조치 완료|완료|성공", case=False, na=False))]
    
    total_items_with_action = len(df[df['조치 여부'] == True])  # 조치가 시도된 항목
    if total_items_with_action > 0:
        completion_rate = len(remediated_safe) / total_items_with_action * 100
        fig.add_trace(
            go.Bar(x=server_stats['호스트'], y=[completion_rate] * len(server_stats), name='조치 완료율(%)', marker_color='blue'),
            row=1, col=2
        )
    else:
        fig.add_trace(
            go.Bar(x=server_stats['호스트'], y=[0] * len(server_stats), name='조치 완료율(%)', marker_color='blue'),
            row=1, col=2
        )
    
    # 전체 보안 상태 분포
    total_safe = server_stats['실질적_양호'].sum()
    total_vulnerable = server_stats['실질적_취약'].sum()
    fig.add_trace(
        go.Pie(
            labels=['실질적 양호', '실질적 취약'], 
            values=[total_safe, total_vulnerable], 
            name="전체분포",
            marker=dict(colors=['green', 'red'])  # 양호=녹색, 취약=빨간색
        ),
        row=2, col=1
    )
    
    # 보안 개선 효과 (3단계 분류)
    fig.add_trace(
        go.Bar(x=server_stats['호스트'], y=server_stats['원래_양호'], name='원래부터 양호', marker_color='#28a745'),
        row=2, col=2
    )
    fig.add_trace(
        go.Bar(x=server_stats['호스트'], y=server_stats['조치_후_양호'], name='조치 후 양호', marker_color='#17a2b8'),
        row=2, col=2
    )
    fig.add_trace(
        go.Bar(x=server_stats['호스트'], y=server_stats['여전히_취약'], name='여전히 취약', marker_color='#dc3545'),
        row=2, col=2
    )
    
    fig.update_layout(height=800, showlegend=True, title_text="서버별 종합 보안 분석 (실질적 상태 반영)")
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
    """실행 타임라인 분석 (올바른 날짜 시간 표시)"""
    log_file = f"logs/ansible_execute_log_{timestamp}.log"
    
    if not os.path.exists(log_file):
        return None
        
    try:
        # timestamp에서 실행 날짜 추출 (예: 20250620_141836)
        execution_date = datetime.strptime(timestamp, "%Y%m%d_%H%M%S").date()
        
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
                        # HH:MM:SS 형식을 실제 datetime으로 변환
                        hour, minute, second = map(int, time_part.split(':'))
                        event_datetime = datetime.combine(execution_date, datetime.min.time().replace(
                            hour=hour, minute=minute, second=second
                        ))
                        
                        timeline_events.append({
                            'start_time': event_datetime,
                            'end_time': event_datetime + pd.Timedelta(seconds=30),  # 30초 지속으로 가정
                            'event': event_part[:50] + '...' if len(event_part) > 50 else event_part,
                            'type': 'TASK' if 'TASK' in event_part else 'PLAY'
                        })
                except:
                    continue
        
        if timeline_events:
            timeline_df = pd.DataFrame(timeline_events)
            
            # Gantt 차트 스타일의 타임라인
            fig = px.timeline(
                timeline_df,
                x_start="start_time",
                x_end="end_time", 
                y="event",
                color="type",
                title=f"Ansible 실행 타임라인 ({execution_date.strftime('%Y-%m-%d')})",
                color_discrete_map={
                    'TASK': '#1f77b4',
                    'PLAY': '#ff7f0e'
                }
            )
            
            # x축 시간 형식 개선
            fig.update_xaxes(
                title="실행 시간",
                tickformat="%H:%M:%S"
            )
            fig.update_yaxes(title="실행 항목")
            fig.update_layout(height=600, showlegend=True)
            return fig
            
    except Exception as e:
        st.error(f"타임라인 생성 실패: {str(e)}")
    
    return None

def calculate_execution_time(timestamp):
    """로그에서 실행 시간을 계산"""
    log_file = f"logs/ansible_execute_log_{timestamp}.log"
    
    if not os.path.exists(log_file):
        return None
        
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            log_content = f.read()
        
        lines = log_content.split('\n')
        start_time = None
        end_time = None
        
        # 시작 시간과 종료 시간 찾기
        for line in lines:
            if '[' in line and ']' in line:
                try:
                    time_part = line.split('[')[1].split(']')[0]
                    # 첫 번째 타임스탬프를 시작 시간으로
                    if start_time is None:
                        start_time = time_part
                    # 마지막 타임스탬프를 종료 시간으로 계속 업데이트
                    end_time = time_part
                except:
                    continue
        
        if start_time and end_time:
            # 시간 형식: HH:MM:SS
            start_h, start_m, start_s = map(int, start_time.split(':'))
            end_h, end_m, end_s = map(int, end_time.split(':'))
            
            start_seconds = start_h * 3600 + start_m * 60 + start_s
            end_seconds = end_h * 3600 + end_m * 60 + end_s
            
            # 날짜가 바뀐 경우 처리
            if end_seconds < start_seconds:
                end_seconds += 24 * 3600
            
            duration_seconds = end_seconds - start_seconds
            
            # 분:초 형식으로 변환
            minutes = duration_seconds // 60
            seconds = duration_seconds % 60
            
            return f"{minutes}분 {seconds}초"
            
    except Exception as e:
        return None
    
    return None
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

def get_log_content(timestamp):
    """로그 파일 내용을 반환하는 함수 (다운로드 버튼 없이)"""
    log_file = f"logs/ansible_execute_log_{timestamp}.log"
    
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            st.error(f"로그 파일 읽기 실패: {str(e)}")
            return None
    else:
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
        
        # ⭐ 실질적 양호 상태 계산 (조치 완료도 양호로 간주)
        df['실질적_양호상태'] = (
            (df['전체 취약 여부'] == False) | 
            (df['조치 결과'].str.contains("조치 완료|완료|성공", case=False, na=False))
        )
        
        # 성공 메시지와 기본 통계 (실질적 상태 기준)
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.success(f"✅ **{len(df)}**개 점검 항목")
        with col2:
            st.info(f"🖥️ **{len(result_data['servers'])}**개 서버")
        with col3:
            st.warning(f"📁 **{result_data['total_files']}**개 결과 파일")
        with col4:
            # 실질적 취약점 수 (조치 완료 제외)
            actual_vulnerable_count = len(df[df['실질적_양호상태'] == False])
            if actual_vulnerable_count > 0:
                st.error(f"⚠️ **{actual_vulnerable_count}**개 실질적 취약점")
            else:
                st.success("🛡️ **모든 취약점 해결됨**")
        
    except Exception as e:
        st.error(f"❌ 데이터 파싱 중 오류 발생: {str(e)}")
        return
    
    # 탭 구성 (파일 시스템 분석 제거)
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 종합 대시보드", 
        "🖥️ 서버별 분석", 
        "🔍 취약점 상세", 
        "⏱️ 실행 분석", 
        "📄 원본 데이터"
    ])
    
    with tab1:
        # === 종합 대시보드 ===
        st.header("📋 보안 점검 종합 현황")
        
        # 핵심 메트릭 (실질적 상태 기준으로 모두 수정)
        total_checks = len(df)
        
        # 실질적 취약/양호 상태 계산
        actual_vulnerable_items = len(df[df['실질적_양호상태'] == False])
        actual_safe_items = len(df[df['실질적_양호상태'] == True])
        
        remediation_needed = df[df['조치 결과'].str.contains("수동 조치 필요", case=False, na=False)].shape[0]
        remediation_complete = df[df['조치 결과'].str.contains("완료|성공", case=False, na=False)].shape[0]
        
        # 개선 효과 분석 추가 (실질적 상태 기준)
        originally_safe = df[(df['실질적_양호상태'] == True) & (df['조치 여부'] == False)]
        remediated_safe = df[(df['조치 여부'] == True) & 
                           (df['조치 결과'].str.contains("조치 완료|완료|성공", case=False, na=False))]
        
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("🔍 총 점검 항목", total_checks)
        col2.metric("⚠️ 실질적 취약점", actual_vulnerable_items, delta=f"{(actual_vulnerable_items/total_checks*100):.1f}%")
        col3.metric("✅ 실질적 양호", actual_safe_items, delta=f"{(actual_safe_items/total_checks*100):.1f}%")
        col4.metric("🔧 조치 필요", remediation_needed)
        col5.metric("🛡️ 조치 완료", remediation_complete)
        
        # 보안 개선 효과 메트릭 추가
        st.markdown("### 🚀 보안 개선 효과 분석")
        col1, col2, col3, col4 = st.columns(4)
        
        col1.metric("🟢 원래부터 양호", len(originally_safe), 
                   help="처음 점검 시부터 보안 설정이 올바르게 되어 있던 항목")
        col2.metric("🔄 조치 후 양호", len(remediated_safe), 
                   help="취약점이 발견되었지만 Ansible 자동 조치로 양호해진 항목")
        
        if len(remediated_safe) > 0:
            # 전체 발견된 문제 중에서 자동 해결된 비율
            total_issues_found = len(df[df['조치 여부'] == True])  # 조치가 시도된 항목들
            if total_issues_found > 0:
                improvement_rate = len(remediated_safe) / total_issues_found * 100
                col3.metric("📈 자동 해결율", f"{improvement_rate:.1f}%",
                           help="조치가 시도된 항목 중 성공적으로 해결된 비율")
            else:
                col3.metric("📈 자동 해결율", "0%")
        else:
            col3.metric("📈 자동 해결율", "0%")
            
        col4.metric("🎯 전체 보안율", f"{(actual_safe_items/total_checks*100):.1f}%",
                   help="조치 완료 포함한 실질적으로 양호한 항목의 비율")
        
        st.markdown(" ")
        
        # 보안 개선 효과 차트
        fig_improvement1, fig_improvement2, improvement_data = create_security_improvement_analysis(df)
        if fig_improvement1 and fig_improvement2:
            col1, col2 = st.columns(2)
            with col1:
                st.plotly_chart(fig_improvement1, use_container_width=True)
            with col2:
                st.plotly_chart(fig_improvement2, use_container_width=True)
            
            # 개선 효과 상세 테이블
            with st.expander("📊 보안 개선 효과 상세 통계"):
                st.dataframe(improvement_data['stats'], use_container_width=True, hide_index=True)
                
                if len(improvement_data['remediated_safe']) > 0:
                    st.subheader("🔄 자동 조치로 개선된 항목들")
                    remediated_display = improvement_data['remediated_safe'][['호스트', '작업 설명', '조치 결과']].copy()
                    st.dataframe(remediated_display, use_container_width=True)
                else:
                    st.info("자동 조치로 개선된 항목이 없습니다.")
        
        # 서버 비교 차트 (실질적 상태가 포함된 df 전달)
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
            # 서버별 통계 (실질적 상태 기준) - 2열로 변경
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("📊 점검 현황 (실질적 상태)")
                server_stats = server_df.groupby('호스트').agg({
                    '실질적_양호상태': ['count', lambda x: x.sum(), lambda x: (~x).sum()]
                }).round(2)
                server_stats.columns = ['총점검', '실질적_양호', '실질적_취약']
                st.dataframe(server_stats, use_container_width=True)
            
            with col2:
                st.subheader("🔧 조치 현황")
                # 조치 현황을 더 세분화해서 표시
                remediation_detailed = server_df.groupby('호스트').apply(lambda x: pd.Series({
                    '원래부터 양호': len(x[(x['실질적_양호상태'] == True) & (x['조치 여부'] == False)]),
                    '조치 완료': len(x[x['조치 결과'].str.contains("조치 완료|완료|성공", case=False, na=False)]),
                    '수동 조치 필요': len(x[x['조치 결과'].str.contains("수동 조치 필요", case=False, na=False)]),
                    '조치 불필요': len(x[x['조치 결과'].str.contains("조치 불필요", case=False, na=False)])
                })).fillna(0).astype(int)
                
                st.dataframe(remediation_detailed, use_container_width=True)
            
            # 점검 유형을 별도 행으로 이동
            st.subheader("📋 점검 유형 (전체)")
            task_stats = server_df['작업 설명'].value_counts()  # head(10) 제거
            
            # 표 형태로 변환
            task_df = pd.DataFrame({
                '점검 항목': task_stats.index,
                '점검 횟수': task_stats.values
            })
            
            st.dataframe(task_df, use_container_width=True, hide_index=True)
            
            # 서버별 취약점 히트맵 (실질적 상태 기준)
            if len(result_data['servers']) > 1:
                st.subheader("🔥 서버-취약점 히트맵 (실질적 상태)")
                heatmap_data = df.pivot_table(
                    index='작업 설명', 
                    columns='호스트', 
                    values='실질적_양호상태', 
                    aggfunc=lambda x: (~x).sum(),  # 실질적 취약점 수
                    fill_value=0
                )
                
                if not heatmap_data.empty:
                    fig_heatmap = px.imshow(
                        heatmap_data.values,
                        labels=dict(x="서버", y="점검 항목", color="실질적 취약점 수"),
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
        st.header("🔍 취약점 및 실패 상세 분석")
        
        # 실질적으로 취약한 항목만 표시 (조치 완료 제외)
        vulnerable_df = df[df['실질적_양호상태'] == False]
        
        if len(vulnerable_df) > 0:
            st.subheader(f"⚠️ 실질적 취약점 ({len(vulnerable_df)}개)")
            st.info("💡 '조치 완료'된 항목은 해결된 것으로 간주하여 제외됩니다.")
            
            # 취약점 상세 차트 (실질적 취약점 기준)
            fig1, fig2 = create_vulnerability_details_analysis(vulnerable_df)  # vulnerable_df 사용
            if fig1:
                st.plotly_chart(fig1, use_container_width=True)
            if fig2:
                st.plotly_chart(fig2, use_container_width=True)
                
        else:
            st.success("🛡️ 모든 취약점이 해결되었습니다!")
            st.info("일부 항목은 '조치 완료' 상태로 자동 해결되었습니다.")
        
        # 조치 완료된 항목들도 별도로 표시
        resolved_items = df[(df['조치 여부'] == True) & 
                          (df['조치 결과'].str.contains("조치 완료|완료|성공", case=False, na=False))]
        
        if len(resolved_items) > 0:
            st.subheader(f"✅ 자동 해결된 항목들 ({len(resolved_items)}개)")
            
            with st.expander("🔧 Ansible이 자동으로 해결한 취약점들"):
                for idx, row in resolved_items.iterrows():
                    st.markdown(f"**{row['호스트']}** - {row['작업 설명']}")
                    st.markdown(f"- 상태: {row['조치 결과']}")
                    if row['취약 사유']:
                        st.markdown(f"- 원인: {row['취약 사유']}")
                    st.markdown("---")
        
        # 실질적 취약점이 있는 경우에만 상세 분석 표시
        if len(vulnerable_df) > 0:
            # 취약점 상세 테이블
            st.subheader("📋 실질적 취약점 상세 목록")
            
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
                    options=['전체', '수동 조치 필요', '미조치', '실패'],
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
        
        # 🆕 실패 분석 섹션 추가
        st.markdown("---")
        st.subheader("❌ 실행 실패 분석")
        
        # 실패한 작업 분석
        fig_fail1, fig_fail2, failure_data = create_failure_analysis(df)
        
        if failure_data and 'message' in failure_data:
            st.success("✅ " + failure_data['message'])
        elif failure_data:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("총 실패 작업", failure_data['total_failures'])
            with col2:
                st.metric("영향받은 서버", failure_data['affected_servers'])
            with col3:
                failure_rate = failure_data['total_failures'] / len(df) * 100 if len(df) > 0 else 0
                st.metric("실패율", f"{failure_rate:.1f}%")
            
            # 실패 차트
            if fig_fail1 and fig_fail2:
                col1, col2 = st.columns(2)
                with col1:
                    st.plotly_chart(fig_fail1, use_container_width=True)
                with col2:
                    st.plotly_chart(fig_fail2, use_container_width=True)
            
            # 실패 상세 목록
            with st.expander("🔍 실패한 작업 상세 목록", expanded=False):
                for failure in failure_data['detailed_failures']:
                    st.markdown(f"**{failure['호스트']}** - {failure['작업 설명']}")
                    st.markdown(f"- 실패 사유: {failure['조치 결과']}")
                    if failure['취약 사유']:
                        st.markdown(f"- 원인: {failure['취약 사유']}")
                    st.markdown("---")
        
        # 🆕 접근 불가능한 서버 분석
        st.subheader("🔌 서버 접근성 분석")
        
        fig_unreachable, unreachable_data = create_unreachable_hosts_analysis(df, result_data)
        
        if unreachable_data and 'message' in unreachable_data:
            st.success("✅ " + unreachable_data['message'])
        elif unreachable_data:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("접근 불가 서버", unreachable_data['total_unreachable'])
            with col2:
                st.metric("접근 가능 서버", len(unreachable_data['reachable_servers']))
            with col3:
                st.metric("접근 성공률", f"{unreachable_data['success_rate']:.1f}%")
            
            if fig_unreachable:
                st.plotly_chart(fig_unreachable, use_container_width=True)
            
            # 접근 불가 서버 목록
            if unreachable_data['unreachable_servers']:
                with st.expander("⚠️ 접근 불가능한 서버 목록"):
                    for server in unreachable_data['unreachable_servers']:
                        st.markdown(f"- **{server}**: 네트워크 연결 실패 또는 SSH 접근 불가")
                        
                    st.info("💡 해결 방법: SSH 키 설정, 네트워크 연결, 방화벽 설정을 확인하세요.")
                    
            # 조치 시도했지만 무시된 항목들 별도 표시
            ignored_items = df[(df['조치 여부'] == True) & 
                            (df['조치 결과'].str.contains("무시|ignore", case=False, na=False))]

            if len(ignored_items) > 0:
                st.subheader(f"⚠️ 조치 시도했지만 무시된 항목들 ({len(ignored_items)}개)")
                st.info("💡 이 항목들은 실행 중 문제가 발생했지만 ignore_errors 설정으로 전체 실행은 계속되었습니다.")
                
                with st.expander("🔧 무시된 항목들 상세보기"):
                    for idx, row in ignored_items.iterrows():
                        st.markdown(f"**{row['호스트']}** - {row['작업 설명']}")
                        st.markdown(f"- 상태: {row['조치 결과']}")
                        if row['취약 사유']:
                            st.markdown(f"- 원인: {row['취약 사유']}")
                        st.markdown("---")
    
    with tab4:
        # === 실행 분석 ===
        st.header("⏱️ Ansible 실행 분석")
        
        # 실행 타임라인
        fig_timeline = create_execution_timeline(timestamp)
        if fig_timeline:
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.info("실행 타임라인 데이터를 생성할 수 없습니다.")
        
        # 실행 통계 (실질적 상태 기준)
        st.subheader("📊 실행 통계")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # 실제 실행 시간 계산
            execution_time = calculate_execution_time(timestamp)
            if execution_time:
                st.metric("⏱️ 전체 실행 시간", execution_time)
            
            st.metric("📊 평균 서버당 점검", f"{len(df) / len(result_data['servers']) if result_data['servers'] else 0:.1f}개 점검/서버")
        
        # 🆕 실패 현황 메트릭 추가 (ignore 포함)
        attempted_failed_tasks = len(df[df['조치 결과'].str.contains("실패|오류|ERROR|FAILED|무시|ignore|건너뛰|skip", case=False, na=False)])
        ignored_tasks = len(df[df['조치 결과'].str.contains("무시|ignore", case=False, na=False)])
        unreachable_count = len(set(result_data.get('servers', [])) - set(df['호스트'].unique()))

        col5, col6 = st.columns(2)
        with col5:
            if attempted_failed_tasks > 0:
                st.warning(f"⚠️ **{attempted_failed_tasks}**개 조치 문제")
                if ignored_tasks > 0:
                    st.caption(f"└ 그 중 {ignored_tasks}개는 무시됨")
            else:
                st.success("✅ **모든 조치 성공**")

        with col6:
            if unreachable_count > 0:
                st.warning(f"🔌 **{unreachable_count}**개 서버 접근불가")
            else:
                st.success("🌐 **모든 서버 접근가능**")
        
        with col2:
            # 실질적 성공률
            success_rate = (len(df[df['실질적_양호상태'] == True]) / len(df) * 100) if len(df) > 0 else 0
            st.metric("✅ 실질적 성공률", f"{success_rate:.1f}%")
            
            automation_rate = (len(df[df['조치 결과'].str.contains("완료", case=False, na=False)]) / len(df) * 100) if len(df) > 0 else 0
            st.metric("🔧 자동 조치율", f"{automation_rate:.1f}%")
        
        with col3:
            st.metric("🖥️ 점검된 서버 수", len(result_data['servers']))
            st.metric("📋 점검 항목 유형", len(result_data['check_types']))
        
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
    
    with tab5:
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
            default=['호스트', '작업 설명', '진단 결과', '실질적_양호상태', '조치 결과']
        )
        
        if selected_columns:
            # 필터링 옵션 (실질적 상태 기준)
            col1, col2 = st.columns(2)
            
            with col1:
                show_only_vulnerable = st.checkbox("실질적 취약점만 표시", value=False)
            
            with col2:
                show_only_manual = st.checkbox("수동 조치 필요 항목만 표시", value=False)
            
            # 필터 적용
            filtered_df = df.copy()
            
            if show_only_vulnerable:
                filtered_df = filtered_df[filtered_df['실질적_양호상태'] == False]
            
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
        
        col1, col2, col3, col4 = st.columns(4)
        
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
            # 실질적 취약점만 CSV 다운로드
            vulnerable_only = df[df['실질적_양호상태'] == False]
            if len(vulnerable_only) > 0:
                vulnerable_csv = vulnerable_only.to_csv(index=False, encoding='utf-8-sig')
                st.download_button(
                    "⚠️ 실질적 취약점 CSV 다운",
                    vulnerable_csv,
                    f"actual_vulnerabilities_{timestamp}.csv",
                    "text/csv"
                )
            else:
                st.button("⚠️ 실질적 취약점 CSV 다운", disabled=True, help="실질적 취약점이 없습니다")
        
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
                
        with col4:
            # 로그 파일 다운로드 추가
            log_content = get_log_content(timestamp)
            if log_content:
                st.download_button(
                    "📥 실행 로그 다운로드",
                    log_content,
                    f"ansible_log_{timestamp}.log",
                    "text/plain",
                    key=f"download_log_{timestamp}"
                )
            else:
                st.button("📥 실행 로그 다운로드", disabled=True, help="로그 파일을 찾을 수 없습니다")
                
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
                    matching_lines = [line for line in log_content.split('\n') if search_term.lower() in line.lower()]
                    
                    st.info(f"검색 결과: {len(matching_lines)}개 라인에서 '{search_term}' 발견")
                    
                    if matching_lines:
                        st.markdown("**검색 결과 미리보기 (최대 10개):**")
                        for line in matching_lines[:10]:
                            st.code(line.strip())
                        st.markdown("---")
                
                # 전체 로그 표시 (바로 표시)
                st.code(log_content, language="text")
                
            except Exception as e:
                st.error(f"로그 파일 읽기 실패: {str(e)}")
        else:
            st.warning(f"로그 파일을 찾을 수 없습니다: {log_file}")

if __name__ == "__main__":
    main()