import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_custom(sender_email, sender_password, receiver_email, subject, body, smtp_server="smtp.gmail.com", smtp_port=587):
    """
    Send a plain text email via SMTP.

    Args:
        sender_email (str): Sender's email address.
        sender_password (str): Sender's email password or app password.
        receiver_email (str): Receiver's email address.
        subject (str): Subject of the email.
        body (str): Body content of the email.
        smtp_server (str): SMTP server address (default: Gmail).
        smtp_port (int): SMTP port (default: 587 for TLS).
    """
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            print(f"✅ Email sent to {receiver_email}")
    except Exception as e:
        print(f"❌ Failed to send email to {receiver_email}: {e}")

send_email_custom(
    sender_email="umaransari220457@acropolis.in",
    sender_password="M@nira786",
    receiver_email="umaransari4444r@example.com",
    subject="Test Message",
    body="This is a test email from Python!"
)