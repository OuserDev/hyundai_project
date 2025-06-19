import json
import pandas as pd
import plotly.express as px
import streamlit as st
from datetime import datetime

def parse_single_result(data):
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

def main():
    st.set_page_config(page_title="보안 진단 대시보드", layout="wide")
    st.title("🔒 보안 진단 결과 대시보드")

    uploaded_files = st.file_uploader("📂 보안 진단 JSON 파일 업로드", type="json", accept_multiple_files=True)

    if uploaded_files:
        all_dataframes = []

        for uploaded_file in uploaded_files:
            try:
                data = json.load(uploaded_file)

                if isinstance(data, list):
                    df = parse_multiple_results(data)
                elif isinstance(data, dict):
                    df = parse_single_result(data)
                else:
                    st.error(f"❌ 파일 {uploaded_file.name} 은(는) 지원하지 않는 JSON 형식입니다.")
                    continue

                all_dataframes.append(df)

            except Exception as e:
                st.error(f"❌ 파일 {uploaded_file.name} 처리 중 오류 발생: {e}")

        if not all_dataframes:
            st.warning("📁 유효한 JSON 파일이 없습니다.")
            return

        df = pd.concat(all_dataframes, ignore_index=True)

        st.markdown("---")
        st.subheader("📋 요약 통계")

        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("총 호스트 수", len(df))
        col2.metric("취약 호스트 수", df[df["전체 취약 여부"] == True].shape[0])
        col3.metric("양호 호스트 수", df[df["전체 취약 여부"] == False].shape[0])

        mitigation_success = df["조치 결과"].str.contains("성공|완료|ok|OK|Success", case=False, na=False).sum()
        mitigation_failed = df["조치 결과"].str.contains("실패|fail|error", case=False, na=False).sum()

        col4.metric("🛠️ 조치 완료 (Mitigated)", mitigation_success)
        col5.metric("⚠️ 조치 실패 (Remediation Failed)", mitigation_failed)

        st.markdown(" ")

        summary_data = pd.DataFrame({
            "항목": ["총 호스트 수", "취약 호스트 수", "양호 호스트 수", "조치 완료", "조치 실패"],
            "개수": [len(df),
                   df[df["전체 취약 여부"] == True].shape[0],
                   df[df["전체 취약 여부"] == False].shape[0],
                   mitigation_success,
                   mitigation_failed]
        })

        color_map = {
            "총 호스트 수": "#A9A9A9",   # 검정
            "취약 호스트 수": "#FF0000", # 빨강
            "양호 호스트 수": "#0000FF", # 파랑
            "조치 완료": "#00BFFF",      # 하늘
            "조치 실패": "#FF8C00"       # orange
        }

        fig_summary = px.bar(summary_data,
                             x="항목",
                             y="개수",
                             color="항목",
                             text="개수",
                             color_discrete_map=color_map)
        fig_summary.update_layout(showlegend=False)
        st.plotly_chart(fig_summary, use_container_width=True)

        st.markdown("---")
        st.subheader("🕒 조치 이력 타임라인")
        try:
            df["조치 시간"] = pd.to_datetime(df["조치 시간"], errors='coerce')
            timeline = df[df["조치 시간"].notnull()].sort_values("조치 시간")
            fig3 = px.scatter(timeline, x="조치 시간", y="호스트", color="조치 결과",
                              title="조치 시간별 조치 내역", symbol="조치 결과")
            st.plotly_chart(fig3, use_container_width=True)
        except:
            st.info("조치 시간 형식이 올바르지 않거나 누락되어 있어 타임라인을 표시할 수 없습니다.")

        st.markdown("---")
        st.subheader("🔍 세부 데이터 보기")
        st.dataframe(df)

        csv = df.to_csv(index=False)
        st.download_button("⬇️ CSV 다운로드", csv, "security_report.csv", "text/csv")

if __name__ == "__main__":
    main()
