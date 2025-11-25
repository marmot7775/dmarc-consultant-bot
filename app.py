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

            # New section - DMARC vs DMARCbis assessment
            dmarc_analysis = result.get("dmarc_analysis")
            if dmarc_analysis:
                st.subheader("DMARC vs DMARCbis assessment")
                st.write(dmarc_analysis.get("overall_assessment"))

                tags = dmarc_analysis.get("tags", {})
                if tags:
                    st.markdown("**Parsed tags:**")
                    for k, v in tags.items():
                        st.write(f"- `{k}` = `{v}`")

                issues = dmarc_analysis.get("issues") or []
                if issues:
                    st.markdown("**Issues to review:**")
                    for item in issues:
                        st.write(f"- {item}")

                notes = dmarc_analysis.get("dmarchbis_notes") or []
                if notes:
                    st.markdown("**DMARCbis guidance notes:**")
                    for item in notes:
                        st.write(f"- {item}")

            st.subheader("Recommended starting DMARC record")
            st.code(result["recommended_record"], language="text")

            st.subheader("Details")
            for item in result["details"]:
                st.write(f"- {item}")
