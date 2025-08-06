import streamlit as st
import openai

openai.api_key = st.secrets["openai_api_key"]

st.title("DMARC Consultant Bot")

user_level = st.selectbox(
    "Choose your technical level:",
    ["Executive", "Mid-level IT", "Email Security Pro"]
)

user_question = st.text_area("Ask your DMARC question:")

if st.button("Get Advice"):
    if user_question:
        system_prompt = f"""
        You are a friendly but highly competent DMARC expert helping a {user_level}.
        Explain things clearly, using language appropriate for a {user_level}.
        Focus on the key ideas and keep it as brief as possible while remaining accurate.
        """

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_question}
            ]
        )

        st.markdown(response["choices"][0]["message"]["content"])
    else:
        st.warning("Please enter a question.")