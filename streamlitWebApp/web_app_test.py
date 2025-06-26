"""
웹 애플리케이션 보안 테스트 페이지
"""
import streamlit as st

def main():
    """웹 애플리케이션 테스트 메인 페이지"""
    
    # 메인 헤더
    st.title("🕷️ 웹 애플리케이션 보안 테스트")
    
    # 뒤로가기 버튼
    if st.button("⬅️ 정적분석으로 돌아가기"):
        st.query_params.clear()
        st.rerun()
    
    st.markdown("---")
    
    # 간단한 테스트 내용
    st.header("🧪 웹 애플리케이션 동적 보안 테스트")
    st.markdown("SQL Injection, XSS, CSRF 등 웹 취약점 테스트를 수행합니다.")

if __name__ == "__main__":
    main()