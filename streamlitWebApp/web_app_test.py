"""
웹 애플리케이션 보안 테스트 페이지
"""
import streamlit as st

def main():
    """웹 애플리케이션 테스트 메인 페이지"""
    
    # 메인 헤더
    st.title("Askable: ansible 기반 서버 취약점 자동 점검 시스템")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("📋 정적 분석 (KISA 가이드)", use_container_width=True, key="btn_back_from_kisa"):
            st.query_params.clear()  # 모든 쿼리 파라미터 제거해서 메인으로
            st.rerun()

    with col2:
        if st.button("🌐 포트 스캐닝 (Dynamic Analysis)", use_container_width=True, key="btn_back_from_dynamic"):
            st.query_params.update({"page": "port_scanning"})
            st.rerun()
            
    st.header("🕷️ 동적 분석 - 웹 애플리케이션 테스트")
    st.markdown("SQL Injection, XSS, CSRF 등 웹 취약점 테스트를 수행합니다.")
    st.markdown("---")

if __name__ == "__main__":
    main()