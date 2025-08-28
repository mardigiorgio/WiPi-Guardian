# src/wids/alerts.py
import json, http.client, urllib.parse, ssl
from email.message import EmailMessage
import smtplib

def send_discord(webhook_url: str, text: str):
    parsed = urllib.parse.urlparse(webhook_url)
    body = json.dumps({"content": text})
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(parsed.netloc, context=ctx, timeout=5)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    if resp.status >= 300:
        raise RuntimeError(f"Discord webhook failed: {resp.status}")

def send_email(smtp_host: str, smtp_port: int, username: str, password: str,
               from_addr: str, to_addrs: list[str], subject: str, body: str):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body)
    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
        s.starttls()
        if username:
            s.login(username, password)
        s.send_message(msg)
