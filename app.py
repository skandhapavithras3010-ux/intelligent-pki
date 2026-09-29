import streamlit as st

from src.ipki.pipeline import analyze
from src.ipki.report import make_json_report


st.set_page_config(
    page_title="Intelligent PKI",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Intelligent PKI")
st.write("Explainable X.509 Certificate Trust Assessment")


certificate = st.file_uploader(
    "Upload leaf certificate",
    type=["pem", "crt"]
)

intermediates = st.file_uploader(
    "Upload intermediate certificates (optional)",
    type=["pem", "crt"],
    accept_multiple_files=True
)

hostname = st.text_input(
    "Hostname (optional)",
    placeholder="example.com"
)


if st.button("Analyze Certificate"):

    if certificate is None:
        st.error("Please upload a certificate.")
    else:
        with st.spinner("Analyzing certificate..."):

            result = analyze(
                pem_bytes=certificate.getvalue(),
                intermediates=[
                    cert.getvalue()
                    for cert in intermediates
                ],
                hostname=hostname or None
            )

        fusion = result["fusion"]

        st.subheader("Final Verdict")

        if fusion.verdict == "TRUSTED":
            st.success(f"TRUSTED — Score: {fusion.score:.2f}")
        elif fusion.verdict == "CAUTION":
            st.warning(f"CAUTION — Score: {fusion.score:.2f}")
        else:
            st.error(f"UNTRUSTED — Score: {fusion.score:.2f}")

        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "ML Trust Score",
                f"{result['ml_score']:.2f}"
            )

        with col2:
            st.metric(
                "Chain Status",
                result["chain"].status
            )

        st.subheader("PKI Policy Results")

        for item in result["policy"]:
            st.write(
                f"**{item.rule}** — `{item.status}` — {item.message}"
            )

        st.subheader("SHAP Explanations")

        for explanation in result["explanations"]:
            st.write(
                f"**{explanation['feature']}** → "
                f"impact: `{explanation['impact']:.4f}` | "
                f"rule: `{explanation['rule']}` | "
                f"status: `{explanation['status']}`"
            )

        report = make_json_report(result)

        st.download_button(
            label="Download JSON Report",
            data=report,
            file_name="certificate_report.json",
            mime="application/json"
        )