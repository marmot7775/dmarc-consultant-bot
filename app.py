import streamlit as st
from dmarc_agent import analyze_domain, answer_freeform_question

st.set_page_config(page_title="DMARC and Email Security Bot")

st.title("DMARC and Email Security Bot")
st.write(
    "Check a domain's DMARC and SPF configuration and ask questions about email security, "
    "deliverability, and DNS."
)

tab1, tab2 = st.tabs(["Domain analysis", "Ask a question"])

# -------------------------------------------------------------------
# Domain analysis tab
# -------------------------------------------------------------------
with tab1:
    st.header("Domain analysis")

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

            dns_info = result.get("dns", {})
            existing_dmarc = dns_info.get("existing_dmarc")
            existing_spf = dns_info.get("existing_spf")
            dns_note = dns_info.get("note")

            st.subheader("Existing DNS records")

            if existing_dmarc:
                st.markdown(f"**DMARC (at _dmarc.{domain}):**")
                st.code(existing_dmarc, language="text")
            else:
                st.info(f"No DMARC record found at _dmarc.{domain}.")

            if existing_spf:
                st.markdown(f"**SPF (at {domain}):**")
                st.code(existing_spf, language="text")
            else:
                st.info(f"No SPF record found at {domain}.")

            if dns_note:
                st.warning(dns_note)

            dmarc_analysis = result.get("dmarc_analysis")
            if dmarc_analysis:
                st.subheader("DMARC vs DMARCbis assessment")

                overall = dmarc_analysis.get("overall_assessment")
                if overall:
                    st.write(overall)

                tags = dmarc_analysis.get("tags") or {}
                if tags:
                    st.markdown("**Parsed DMARC tags:**")
                    for k, v in tags.items():
                        st.write(f"- {k} = {v}")

                dmarc_issues = dmarc_analysis.get("issues") or []
                if dmarc_issues:
                    st.markdown("**DMARC issues to review:**")
                    for item in dmarc_issues:
                        st.write(f"- {item}")

                dmarc_notes = dmarc_analysis.get("dmarchbis_notes") or []
                if dmarc_notes:
                    st.markdown("**DMARCbis guidance notes:**")
                    for item in dmarc_notes:
                        st.write(f"- {item}")

            spf_analysis = result.get("spf_analysis")
            if spf_analysis:
                st.subheader("SPF analysis")

                dns_lookups = spf_analysis.get("dns_lookups")
                if dns_lookups is not None:
                    st.write(f"SPF DNS lookups: {dns_lookups}")

                spf_issues = spf_analysis.get("issues") or []
                if spf_issues:
                    st.markdown("**SPF issues to review:**")
                    for item in spf_issues:
                        st.write(f"- {item}")

                spf_notes = spf_analysis.get("notes") or []
                if spf_notes:
                    st.markdown("**SPF notes:**")
                    for item in spf_notes:
                        st.write(f"- {item}")

            st.subheader("Recommended starting DMARC record")
            st.code(result["recommended_record"], language="text")

            st.subheader("Implementation
