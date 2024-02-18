import datetime
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def generate_random_word(length):
    letters = "abcdefghijklmnopqrstuvwxyz"
    return "".join(random.choice(letters) for _ in range(length))


SMTP_SERVER = "email-smtp.us-east-1.amazonaws.com"
SMTP_PORT = 587
USERNAME = "<create iam sender user via ses>"
PASSWORD = "<create iam sender user via ses>"
FROM = "noreply@domain.cloud"  # Email should be verified in particular region via ses
TO = "to.user@domain.com"  # In order to send to rundom address you should move ses from a sansbox
SUBJECT = f"Currently: {datetime.date.today()}"
BODY = f"Hi,\njust some text here {generate_random_word(12)} for testing purpose only"

msg = MIMEMultipart()
msg["From"] = FROM
msg["To"] = TO
msg["Subject"] = SUBJECT

msg.attach(MIMEText(BODY, "plain"))

try:
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(USERNAME, PASSWORD)
    server.sendmail(FROM, TO, msg.as_string())
    print(f"Email {SUBJECT} sent successfully!")
except Exception as e:
    print(f"Failed to send email: {e}")
finally:
    server.quit()
