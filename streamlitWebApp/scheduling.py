"""
스케줄링 페이지 - 주기적 보안 점검 스케줄 관리
"""
import streamlit as st

def main():
    """스케줄링 메인 페이지"""
    
    # 메인 헤더
    st.title("Askable: ansible 기반 서버 취약점 자동 점검 시스템")
            
    st.header("⏰ 스케줄링 (Scheduling)")
    st.markdown("주기적 보안 점검 스케줄을 설정하고 관리합니다.")
    st.info("💡 이 기능은 추후 구현 예정입니다.")

if __name__ == "__main__":
    main()