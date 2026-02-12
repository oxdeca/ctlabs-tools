# -----------------------------------------------------------------------------
# File    : ctlabs-tools/postfix/app.py
# License : MIT
# -----------------------------------------------------------------------------

import streamlit as st
import pandas as pd
import json, base64, os, socket, ssl, smtplib, re, hashlib
import dns.resolver
import dns.exception
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

class MailModel:
    def __init__(self, config_path="smtp_config.enc", logs_path="mail_logs.jsonl"):
        self.config_path = config_path
        self.logs_path = logs_path
        os.makedirs(os.path.dirname(os.path.abspath(__file__)), exist_ok=True)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def load_config(self, master_pwd: str) -> Optional[Dict]:
        if not os.path.exists(self.config_path): return None
        try:
            with open(self.config_path, "rb") as f: data = json.load(f)
            salt = base64.b64decode(data["salt"])
            token = base64.b64decode(data["token"])
            fernet = Fernet(self._derive_key(master_pwd, salt))
            decrypted = fernet.decrypt(token)
            return json.loads(decrypted.decode())
        except Exception: return None

    def save_config(self, master_pwd: str, settings: Dict) -> bool:
        try:
            salt = os.urandom(16)
            fernet = Fernet(self._derive_key(master_pwd, salt))
            token = fernet.encrypt(json.dumps(settings).encode())
            with open(self.config_path, "w") as f:
                json.dump({"salt": base64.b64encode(salt).decode(), "token": base64.b64encode(token).decode()}, f)
            return True
        except Exception: return False

    def load_logs(self) -> pd.DataFrame:
        if not os.path.exists(self.logs_path):
            return pd.DataFrame(columns=["timestamp", "type", "domain", "result", "details"])
        try:
            df = pd.read_json(self.logs_path, lines=True)
            for col in ["timestamp", "type", "domain", "result", "details"]:
                if col not in df.columns: df[col] = ""
            return df[["timestamp", "type", "domain", "result", "details"]]
        except Exception:
            return pd.DataFrame(columns=["timestamp", "type", "domain", "result", "details"])

    def save_logs(self, df: pd.DataFrame) -> bool:
        try:
            df.to_json(self.logs_path, orient="records", lines=True, date_format="iso")
            return True
        except Exception: return False

    def append_log(self, entry: Dict) -> bool:
        try:
            entry.setdefault("timestamp", datetime.now().isoformat())
            with open(self.logs_path, "a") as f: f.write(json.dumps(entry) + "\n")
            return True
        except Exception: return False

class MailController:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    def _safe_query(self, qname: str, rdtype: str = "TXT") -> List[str]:
        try:
            answers = self.resolver.resolve(qname, rdtype, raise_on_no_answer=False)
            results = []
            for ans in answers:
                if hasattr(ans, 'strings'):
                    concatenated = b''.join(ans.strings).decode('utf-8', errors='replace')
                    results.append(concatenated)
                elif hasattr(ans, 'to_text'):
                    txt = ans.to_text()
                    if txt.startswith('"') and txt.endswith('"'): txt = txt[1:-1]
                    results.append(txt)
            return results
        except (dns.exception.DNSException, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []

    def _lookup_asn(self, ip: str) -> str:
        try:
            rev = '.'.join(reversed(ip.split('.'))) + ".origin.asn.cymru.com"
            answers = self.resolver.resolve(rev, 'TXT')
            txt = answers[0].to_text().strip('"')
            parts = txt.split('|')
            if len(parts) >= 4: return f"AS{parts[0].strip()} ({parts[2].strip()})"
            return parts[0].strip()
        except Exception:
            return "Unknown provider"

    def check_spf(self, domain: str) -> Dict[str, Any]:
        records = self._safe_query(domain)
        spf = next((r for r in records if r.startswith("v=spf1")), None)
        if not spf:
            return {"raw": None, "error": "No SPF record found", "explanation": "SPF not configured → Receivers may reject emails"}

        mechanisms = []
        current = ""
        for part in spf.replace("v=spf1", "").split():
            if part.startswith(("ip4:", "ip6:", "include:", "a:", "mx:", "-all", "~all", "+all", "?all")):
                if current: mechanisms.append(current.strip())
                current = part
            else:
                current += " " + part
        if current: mechanisms.append(current.strip())

        ip4s, includes, a_mechs = [], [], []
        for m in mechanisms:
            if m.startswith("ip4:"): ip4s.append(m.split(":",1)[1])
            elif m.startswith("include:"): includes.append(m.split(":",1)[1])
            elif m.startswith("a"): a_mechs.append(m)

        ip_providers = {ip: self._lookup_asn(ip.split('/')[0]) for ip in ip4s if '/' in ip or re.match(r'\d+\.\d+\.\d+\.\d+', ip.split('/')[0])}

        policy = next((m for m in mechanisms if m in ["-all", "~all", "+all", "?all"]), "~all")
        policy_explain = {
            "-all": "✅ Strict: Non-listed IPs are rejected",
            "~all": "⚠️ Softfail: Non-listed IPs accepted but marked",
            "+all": "❌ Dangerous: Accepts ALL IPs (defeats SPF purpose)",
            "?all": "❔ Neutral: No policy statement"
        }.get(policy, "Unknown policy")

        return {
            "raw": spf,
            "mechanisms": mechanisms,
            "ip4s": ip4s,
            "includes": includes,
            "a_mechs": a_mechs,
            "ip_providers": ip_providers,
            "policy": policy,
            "policy_explain": policy_explain,
            "explanation": "SPF publishes allowed sending IPs. Critical limitation: Checks envelope sender (Return-Path), NOT the visible 'From:' header. Without DMARC alignment, spoofers can bypass SPF."
        }

    def check_dmarc(self, domain: str) -> Dict[str, Any]:
        records = self._safe_query(f"_dmarc.{domain}")
        dmarc = next((r for r in records if r.startswith("v=DMARC1")), None)
        if not dmarc:
            return {
                "raw": None,
                "error": "No DMARC record found",
                "explanation": "⚠️ Without DMARC:\n• No enforcement of SPF/DKIM results\n• No reporting on spoofing attempts\n• High phishing risk\n\n💡 DMARC is the ENFORCER that ties SPF/DKIM to the 'From:' header via alignment checks."
            }

        tags = {}
        for part in dmarc.replace("v=DMARC1", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                tags[k] = v

        policy = tags.get("p", "none")
        aspf = tags.get("aspf", "r")
        adkim = tags.get("adkim", "r")
        
        policy_explain = {
            "none": "🔍 Monitor mode only (no enforcement)",
            "quarantine": "⚠️ Quarantine mode (send to spam)",
            "reject": "🚫 Reject mode (block message)"
        }.get(policy, "Unknown policy")

        return {
            "raw": dmarc,
            "tags": tags,
            "policy": policy,
            "policy_explain": policy_explain,
            "alignment": {"spf": aspf, "dkim": adkim},
            "explanation": f"""
🔐 DMARC POLICY: {policy_explain}

⚖️ ALIGNMENT MODE (Critical for security):
• SPF alignment (aspf={aspf}): {'STRICT' if aspf == 's' else 'RELAXED'}
  → Envelope sender domain must {'EXACTLY MATCH' if aspf == 's' else 'be parent/subdomain of'} 'From:' domain
• DKIM alignment (adkim={adkim}): {'STRICT' if adkim == 's' else 'RELAXED'}
  → DKIM d= domain must {'EXACTLY MATCH' if adkim == 's' else 'be parent/subdomain of'} 'From:' domain

📊 REPORTING:
• Aggregate reports (rua): {tags.get('rua', '❌ Not configured')}
• Forensic reports (ruf): {tags.get('ruf', '❌ Not configured')}

💡 WHY THIS MATTERS:
Without DMARC alignment, attackers can:
1. Pass SPF using their own domain's IP (e.g., @attacker.com)
2. Set visible 'From:' header to victim domain (e.g., @bank.com)
3. Email passes SPF but spoofs the sender → PHISHING SUCCESS
DMARC blocks this by requiring alignment between authenticated domain and 'From:' header.
            """.strip()
        }

    def check_dkim(self, selector: str, domain: str) -> Dict[str, Any]:
        try:
            qname = f"{selector}._domainkey.{domain}"
            records = self._safe_query(qname)
            dkim = records[0] if records else None
            if not dkim or "v=DKIM1" not in dkim:
                return {
                    "raw": None,
                    "exists": False,
                    "explanation": f"❌ No valid DKIM record for selector '{selector}'\n\n💡 DKIM signs outbound emails with a PRIVATE key. Receivers verify using this PUBLIC key from DNS. Without it, emails can't be cryptographically authenticated and may fail DMARC."
                }
            
            tags = {}
            for part in dkim.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    tags[k] = v
            
            key_type = tags.get("k", "rsa").upper()
            algorithms = tags.get("h", "all")
            notes = []
            if "t=y" in dkim: notes.append("⚠️ TEST MODE: Receivers may ignore this key")
            if tags.get("t", "").endswith("s"): notes.append("🔒 Key is for email only (not other services)")
            
            return {
                "raw": dkim,
                "exists": True,
                "selector": selector,
                "key_type": key_type,
                "algorithms": algorithms,
                "notes": notes,
                "explanation": f"""
✅ Valid DKIM record found for selector '{selector}'
• Key type: {key_type}
• Hash algorithms: {algorithms}
{'• ' + ' | '.join(notes) if notes else ''}

🔐 HOW DKIM WORKS:
1. Your mail server signs outbound email with PRIVATE key
2. Receiver fetches this PUBLIC key from DNS at {selector}._domainkey.{domain}
3. Receiver verifies cryptographic signature → Confirms email wasn't altered in transit AND came from your domain

⚠️ CRITICAL NOTE:
DKIM alone doesn't protect the 'From:' header! An attacker could:
- Send from @attacker.com with valid DKIM signature
- Set 'From:' header to @bank.com
→ Email passes DKIM but spoofs sender
✅ DMARC alignment fixes this by requiring DKIM d= domain to match 'From:' domain
                """.strip()
            }
        except Exception as e:
            return {"raw": None, "exists": False, "explanation": f"Lookup error: {str(e)}"}

    def send_test_email(self, config: Dict, from_addr: str, to_addr: str, subject: str, body: str) -> Tuple[bool, str]:
        try:
            msg = f"From: {from_addr}\r\nTo: {to_addr}\r\nSubject: {subject}\r\n\r\n{body}"
            context = ssl.create_default_context()
            if config["port"] == 465:
                with smtplib.SMTP_SSL(config["host"], config["port"], context=context) as server:
                    if config.get("user"): server.login(config["user"], config["password"])
                    server.sendmail(from_addr, [to_addr], msg)
            else:
                with smtplib.SMTP(config["host"], config["port"]) as server:
                    server.ehlo()
                    if server.has_extn("STARTTLS"): server.starttls(context=context); server.ehlo()
                    if config.get("user"): server.login(config["user"], config["password"])
                    server.sendmail(from_addr, [to_addr], msg)
            return True, "Email delivered to recipient's mail server"
        except Exception as e:
            return False, f"SMTP delivery failed: {str(e)}"

def main():
    layout = "wide" if st.query_params.get("layout") == "wide" else "centered"
    st.set_page_config(page_title="PostCheck Lab", layout=layout, menu_items={"About": "v1.5.0 • Educational Email Security Toolkit"})

    st.sidebar.title("🔬 PostCheck Lab")
    st.sidebar.caption("v1.5.0 • 2026-02-08")
    wide_mode = st.sidebar.checkbox("↔️ Wide Mode", value=(layout == "wide"))
    if wide_mode != (layout == "wide"):
        st.query_params.layout = "wide" if wide_mode else "centered"
        st.rerun()
    
    st.sidebar.markdown("---")
    st.sidebar.subheader("🔐 Master Password")
    master_pwd = st.sidebar.text_input("Decrypt SMTP config", type="password", label_visibility="collapsed")
    model = MailModel()
    smtp_config = model.load_config(master_pwd) if master_pwd else None
    
    with st.sidebar.expander("📮 SMTP Config"):
        host = st.text_input("SMTP Host", value=smtp_config.get("host", "") if smtp_config else "")
        port = st.number_input("Port", 1, 65535, smtp_config.get("port", 587) if smtp_config else 587)
        user = st.text_input("Username", value=smtp_config.get("user", "") if smtp_config else "")
        pwd = st.text_input("Password", type="password")
        if st.button("💾 Save Encrypted"):
            if master_pwd and model.save_config(master_pwd, {"host": host, "port": port, "user": user, "password": pwd}):
                st.success("Saved"); smtp_config = model.load_config(master_pwd)
            else: st.error("Need master password")

    st.title("🔬 PostCheck Lab: Email Security Deep Dive")
    
    with st.expander("🎓 How Email Authentication Works (SPF/DKIM/DMARC)"):
        st.markdown("""
### The Authentication Chain

| Protocol | What It Checks | Critical Weakness Without DMARC |
|----------|----------------|---------------------------------|
| **SPF** | "Is this IP allowed to send for `@domain.com`?" | Checks envelope sender (Return-Path), NOT visible `From:` header → Spoofers bypass easily |
| **DKIM** | "Was this email cryptographically signed by domain's private key?" | Signs email content but NOT the `From:` header → Spoofers can sign with their key but fake `From:` |
| **DMARC** | "Do SPF/DKIM PASS *AND* align with `From:` domain?" | **THE ENFORCER**: Blocks spoofing by requiring alignment between authenticated domain and visible sender |

💡 **Golden Rule**: SPF + DKIM without DMARC = Incomplete protection. DMARC is the essential policy layer that makes SPF/DKIM effective against phishing.
        """)

    tab_dns, tab_smtp, tab_logs = st.tabs(["🔍 DNS Analyzer", "✉️ SMTP Tester", "📜 Logs"])

    with tab_dns:
        st.header("🛡️ DNS Security Records Analyzer")
        domain = st.text_input("Domain to Analyze", placeholder="example.com").strip().lower()
        controller = MailController()
        
        col1, col2, col3 = st.columns(3)
        check_spf = col1.button("🛡️ SPF")
        check_dmarc = col2.button("🛡️ DMARC")
        check_dkim = col3.button("🛡️ DKIM")
        dkim_sel = st.text_input("DKIM Selector", placeholder="google, s1, default")
        
        if domain:
            if check_spf:
                with st.spinner("Querying SPF..."): res = controller.check_spf(domain)
                st.subheader("🛡️ SPF Record")
                if res.get("error"): st.error(res["error"])
                else:
                    st.code(res["raw"], language="dns")
                    with st.expander("🎓 What SPF Does & This Record's Meaning"):
                        st.markdown(f"""
**Purpose**: Prevents sender address forgery by publishing *allowed sending IPs* for your domain.

⚠️ **Critical Limitation**: SPF checks the *envelope sender* (Return-Path), NOT the `From:` header users see. 
Spoofers can pass SPF but fake the `From:` address → **DMARC alignment fixes this**.

**Policy Analysis**: `{res['policy']}` → {res['policy_explain']}

**Allowed Infrastructure**:
                        """)
                        if res["ip4s"]:
                            st.markdown("**Direct IP Ranges**:")
                            for ip in res["ip4s"]:
                                provider = res["ip_providers"].get(ip, "Unknown")
                                st.caption(f"`{ip}` → {provider}")
                        if res["includes"]:
                            st.markdown("**Third-Party Senders** (via `include:`):")
                            for inc in res["includes"]: st.caption(f"• `{inc}`")
                        if res["a_mechs"]:
                            st.markdown("**'a' Mechanisms** (resolves domain's A record):")
                            for a in res["a_mechs"]: st.caption(f"`{a}`")
                    model.append_log({"type": "spf_check", "domain": domain, "result": "success", "details": f"policy:{res['policy']}"})
            
            if check_dmarc:
                with st.spinner("Querying DMARC..."): res = controller.check_dmarc(domain)
                st.subheader("🛡️ DMARC Record")
                if res.get("error"): st.error(res["error"])
                else:
                    st.code(res["raw"], language="dns")
                with st.expander("🎓 What DMARC Does (The Essential Enforcer)"):
                    st.markdown(res["explanation"])
                model.append_log({"type": "dmarc_check", "domain": domain, "result": res.get("policy", "none"), "details": res.get("raw", "")[:50]})
            
            if check_dkim and dkim_sel:
                with st.spinner(f"Querying DKIM ({dkim_sel})..."): res = controller.check_dkim(dkim_sel, domain)
                st.subheader(f"🛡️ DKIM Record: `{dkim_sel}`")
                if res["exists"]:
                    st.code(res["raw"], language="dns")
                    with st.expander("🎓 What DKIM Does & This Record's Meaning"):
                        st.markdown(res["explanation"])
                else:
                    st.warning(res["explanation"])
                model.append_log({"type": "dkim_check", "domain": domain, "result": "found" if res["exists"] else "missing", "details": f"selector:{dkim_sel}"})
        else:
            st.info("👆 Enter a domain to analyze its email security posture")

    with tab_smtp:
        st.header("✉️ SMTP Deliverability Test")
        if not smtp_config: st.warning("🔐 Enter Master Password in sidebar to load SMTP config")
        else:
            with st.form("smtp_test"):
                col_a, col_b = st.columns(2)
                from_addr = col_a.text_input("From Address", value=smtp_config.get("user", ""))
                to_addr = col_b.text_input("To Address", placeholder="test@gmail.com")
                subject = st.text_input("Subject", value="PostCheck Lab Test")
                body = st.text_area("Body", value="Test email from educational toolkit", height=120)
                submitted = st.form_submit_button("🚀 Send Test")
            
            if submitted and to_addr:
                with st.spinner("Sending..."): success, msg = MailController().send_test_email(smtp_config, from_addr, to_addr, subject, body)
                if success: st.success(f"✅ {msg}"); model.append_log({"type": "smtp", "domain": to_addr.split('@')[-1], "result": "delivered", "details": subject})
                else: st.error(f"❌ {msg}"); model.append_log({"type": "smtp", "domain": to_addr.split('@')[-1], "result": "failed", "details": msg})

    with tab_logs:
        st.header("📜 Audit Log")
        df = model.load_logs()
        if df.empty:
            st.info("No logs yet. Run DNS checks or SMTP tests to populate logs.")
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.caption("PostCheck Lab v1.5.0 • Educational Email Security Toolkit • 2026-02-08")

if __name__ == "__main__":
    main()
