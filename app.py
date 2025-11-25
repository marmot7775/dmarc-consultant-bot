# app.py
import streamlit as st
from dmarc_agent import analyze_domain, answer_freeform_question

st.set_page_config(page_title="DMARC Consulting Bot")

st.title("DMARC Consulting Bot")
st.write(
    "Ask DMARC and email authentication questions, or analyze a specific domain."
)

tab1, tab2 = st.tabs(["Domain analysis", "Ask a question"])

with tab1:
    domain = st.text_input("Domain", placeholder="example.com")
    rua = st.text_input("RUA address (optional)", placeholder="dmarc-reports@example.com")
    ruf = st.text_input("RUF address (optional)")

    if st.button("Analyze domain"):
        if not domain:
            st.error("Please enter a domain.")
        else:
            result = analyze_domain(domain, rua=rua or None, ruf=ruf or None)
            st.subheader("Summary")
            st.write(result["summary"])

            st.subheader("Recommended DMARC record")
            st.code(result["recommended_record"], language="text")

            st.subheader("Details")
            for item in result["details"]:
                st.write(f"- {item}")

with tab2:
    user_question = st.text_area(
        "Ask a DMARC or email authentication question",
        placeholder="For example: How do I move safely from p=none to p=reject?"
    )

    if st.button("Get answer", key="question_button"):
        if not user_question.strip():
            st.error("Please enter a question.")
        else:
            answer = answer_freeform_question(user_question)
            st.subheader("Answer")
            st.write(answer)
