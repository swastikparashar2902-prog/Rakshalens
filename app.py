import streamlit as st
from analyzer import analyze_url, analyze_text


# Page settings
st.set_page_config(
    page_title="RakshaLens",
    page_icon="🛡️",
    layout="wide"
)


# Header
st.title("🛡️ RakshaLens")
st.subheader("Your Smart Scam Detection Assistant")

st.write(
    "Analyze suspicious links, SMS, WhatsApp messages, "
    "emails and payment requests."
)

st.caption(
    "Privacy-first • Explainable risk analysis • Safe-by-default"
)

st.divider()


# Sidebar
st.sidebar.title("🛡️ RakshaLens")

option = st.sidebar.radio(
    "Choose Analysis Type",
    [
        "🔗 Analyze Link",
        "💬 Analyze Message",
        "📧 Analyze Email",
        "💳 Analyze Payment Request"
    ]
)


# Function to display result
def show_result(result):

    risk = result["risk_level"]
    score = result["score"]

    st.subheader("Risk Decision")

    if risk == "HIGH RISK":
        st.error(f"🔴 {risk}")

    elif risk == "CAUTION":
        st.warning(f"🟡 {risk}")

    else:
        st.success(f"🟢 {risk}")

    st.progress(score / 100)

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Risk Score",
            f"{score}/100"
        )

    with col2:
        st.metric(
            "Confidence",
            f"{result['confidence']}%"
        )

    st.divider()

    st.subheader("🔍 Evidence")

    for reason in result["reasons"]:
        st.write("• " + reason)

    st.divider()

    st.subheader("🛡️ Recommended Action")
    st.info(result["action"])


# Analyze Link
if option == "🔗 Analyze Link":

    st.header("🔗 Analyze a Link")

    url = st.text_input(
        "Paste a suspicious URL",
        placeholder="https://example.com"
    )

    if st.button("Analyze Link"):

        if url:
            result = analyze_url(url)
            show_result(result)

        else:
            st.warning("Please enter a URL first.")


# Analyze Message
elif option == "💬 Analyze Message":

    st.header("💬 Analyze SMS or WhatsApp Message")

    text = st.text_area(
        "Paste the message here",
        height=200,
        placeholder="Paste suspicious SMS or WhatsApp message..."
    )

    if st.button("Analyze Message"):

        if text:
            result = analyze_text(text)
            show_result(result)

        else:
            st.warning("Please enter a message first.")


# Analyze Email
elif option == "📧 Analyze Email":

    st.header("📧 Analyze Email")

    subject = st.text_input("Email Subject")

    body = st.text_area(
        "Email Content",
        height=250
    )

    if st.button("Analyze Email"):

        full_email = subject + " " + body

        if full_email.strip():
            result = analyze_text(full_email)
            show_result(result)

        else:
            st.warning("Please enter email content.")


# Analyze Payment Request
elif option == "💳 Analyze Payment Request":

    st.header("💳 Analyze Payment Request")

    payment_text = st.text_area(
        "Paste payment request details",
        height=200,
        placeholder="Example: You received a message asking you to scan a QR code for a refund..."
    )

    if st.button("Analyze Payment Request"):

        if payment_text:
            result = analyze_text(payment_text)
            show_result(result)

        else:
            st.warning("Please enter payment request details.")


# Footer
st.divider()

st.caption(
    "RakshaLens does not guarantee that content is safe. "
    "Risk decisions are based on detected indicators and available evidence."
)