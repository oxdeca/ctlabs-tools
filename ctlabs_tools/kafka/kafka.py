# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/kakfa/kafka.py
# License : MIT
# -----------------------------------------------------------------------------

import streamlit as st
import pandas as pd
import json
import os
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import base64
from hashlib import sha256
import tempfile
import glob
import sys
from streamlit.web import cli as stcli

try:
    from confluent_kafka import Producer, Consumer
    from confluent_kafka.admin import AdminClient, NewTopic, NewPartitions
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

APP_VERSION = "3.7.0"
CREATED_DATE = "2024-05-22"

def cleanup_old_certs():
    temp_dir = tempfile.gettempdir()
    for f in glob.glob(os.path.join(temp_dir, "ca_*.pem")):
        if time.time() - os.path.getmtime(f) > 3600:
            try:
                os.remove(f)
            except:
                pass

class KafkaModel:
    def __init__(self):
        self.config_file = "kafka_config.enc"
        self.schema = ["timestamp", "user_id", "action"]
        self.valid_actions = ["login", "view_item", "cart_add", "checkout", "logout"]
        if "producer_log" not in st.session_state:
            st.session_state.producer_log = []

    def get_crypto_key(self, password):
        return base64.urlsafe_b64encode(sha256(password.encode()).digest())

    def test_connection(self, broker, client_id, security, user, password, ssl_ca="", ssl_verify=True):
        if not KAFKA_AVAILABLE: 
            return False, "confluent-kafka not installed"
        
        for attempt in range(3):
            try:
                conf = {
                    'bootstrap.servers': broker,
                    'client.id': client_id + f"-test-{int(time.time())}",
                    'security.protocol': security,
                    'socket.timeout.ms': 10000,
                    'connections.max.idle.ms': 10000,
                    'debug': 'security,broker'
                }
                if security in ["SASL_PLAINTEXT", "SASL_SSL", "SASL_LDAP"]:
                    conf.update({
                        'sasl.mechanism': 'PLAIN',
                        'sasl.username': user,
                        'sasl.password': password
                    })
                if security in ["SASL_SSL", "SASL_LDAP"]:
                    if ssl_ca.strip():
                        conf['ssl.ca.location'] = ssl_ca.strip()
                    conf['enable.ssl.certificate.verification'] = ssl_verify
                    conf['ssl.endpoint.identification.algorithm'] = 'none'
                
                admin = AdminClient(conf)
                md = admin.list_topics(timeout=5)
                return True, f"✓ Connected to {len(md.brokers)} broker(s)"
                
            except Exception as e:
                if attempt == 2:
                    return False, str(e)
                time.sleep(1)

    def get_conf(self, saved_conf):
        if not saved_conf: 
            return {}
        base = {
            'bootstrap.servers': saved_conf.get('broker', 'localhost:9092'),
            'client.id': saved_conf.get('client_id', 'streamlit-app') + f"-{int(time.time())}",
            'security.protocol': saved_conf.get('security', 'PLAINTEXT'),
            'socket.timeout.ms': 10000,
            'connections.max.idle.ms': 10000,
            'debug': 'security,broker'
        }
        sec = saved_conf.get('security', 'PLAINTEXT')
        if sec in ["SASL_PLAINTEXT", "SASL_SSL", "SASL_LDAP"]:
            base.update({
                'sasl.mechanism': 'PLAIN',
                'sasl.username': saved_conf.get('sasl_user', ''),
                'sasl.password': saved_conf.get('sasl_pass', '')
            })
        if sec in ["SASL_SSL", "SASL_LDAP"]:
            ca_path = saved_conf.get('ssl_ca', '').strip()
            ssl_verify = saved_conf.get('ssl_verify', True)
            if ca_path:
                base['ssl.ca.location'] = ca_path
            base['enable.ssl.certificate.verification'] = ssl_verify
            base['ssl.endpoint.identification.algorithm'] = 'none'
        return base

    def save_uploaded_ca(self, uploaded_file):
        """Save uploaded CA cert to temporary location"""
        if uploaded_file is None:
            return None
        temp_dir = tempfile.gettempdir()
        ca_path = os.path.join(temp_dir, f"ca_{hash(uploaded_file.name)}_{int(time.time())}.pem")
        with open(ca_path, "wb") as f:
            f.write(uploaded_file.getvalue())
        return ca_path

    def save_pasted_ca(self, ca_content):
        """Save pasted CA cert to temporary location"""
        if not ca_content.strip():
            return None
        temp_dir = tempfile.gettempdir()
        ca_path = os.path.join(temp_dir, f"ca_pasted_{int(time.time())}.pem")
        with open(ca_path, "w") as f:
            f.write(ca_content)
        return ca_path

    def save_config(self, password, data):
        f = Fernet(self.get_crypto_key(password))
        with open(self.config_file, "wb") as f_out:
            f_out.write(f.encrypt(json.dumps(data).encode()))

    def load_config(self, password):
        if not os.path.exists(self.config_file): 
            return None
        try:
            f = Fernet(self.get_crypto_key(password))
            with open(self.config_file, "rb") as f_in:
                return json.loads(f.decrypt(f_in.read()).decode())
        except:
            return "AUTH_ERROR"

    def list_topics(self, conf):
        if not KAFKA_AVAILABLE or not conf: 
            return []
        try:
            admin = AdminClient(self.get_conf(conf))
            topics = admin.list_topics(timeout=5).topics
            return [t for t in topics.keys() if not t.startswith("__")]
        except:
            return []

    def get_details(self, conf, topic):
        if not KAFKA_AVAILABLE: 
            return None
        try:
            md = AdminClient(self.get_conf(conf)).list_topics(timeout=3)
            if topic not in md.topics: 
                return None
            data = []
            for pid, p in md.topics[topic].partitions.items():
                isr_count = len(p.isrs)
                replicas = len(p.replicas)
                under_replicated = isr_count < replicas
                data.append({
                    "Partition": pid,
                    "Leader": p.leader,
                    "Replicas": str(p.replicas),
                    "ISR Count": isr_count,
                    "Under-Replicated": "⚠️ Yes" if under_replicated else "No"
                })
            return pd.DataFrame(data)
        except:
            return None

    def create_topic(self, conf, name, partitions, replicas):
        if not KAFKA_AVAILABLE: 
            return False, "Library missing"
        try:
            admin = AdminClient(self.get_conf(conf))
            topic_str = str(name).strip()
            admin.create_topics([
                NewTopic(topic_str, int(partitions), int(replicas))
            ])[topic_str].result()
            return True, f"✓ Topic '{topic_str}' created"
        except Exception as e:
            return False, str(e)

    def delete_topic(self, conf, name):
        if not KAFKA_AVAILABLE: 
            return False, "Library missing"
        try:
            admin = AdminClient(self.get_conf(conf))
            topic_str = str(name).strip()
            admin.delete_topics([topic_str])[topic_str].result()
            return True, f"✓ Topic '{topic_str}' deleted"
        except Exception as e:
            return False, str(e)

    def update_partitions(self, conf, topic, new_count):
        if not KAFKA_AVAILABLE: 
            return False, "Library missing"
        try:
            admin = AdminClient(self.get_conf(conf))
            topic_str = str(topic).strip()
            new_count = int(new_count)
            new_part_spec = NewPartitions(topic_str, new_count)
            futures = admin.create_partitions([new_part_spec])
            futures[topic_str].result()
            return True, f"✓ Partitions increased to {new_count}"
        except Exception as e:
            err = str(e).lower()
            if "increase" in err or "decrease" in err:
                return False, "Kafka only supports INCREASING partitions (must be > current)"
            return False, str(e)

    def produce(self, conf, topic, message, ttl=0, one_time=False, encrypt=False, enc_key=""):
        if not KAFKA_AVAILABLE: 
            return False, "Library missing"
        # Don't validate schema for custom messages
        if not isinstance(message, dict):
            return False, "Message must be a dictionary"
        
        payload = message.copy()
        meta = {"created_at": datetime.now().isoformat()}
        if ttl > 0: 
            meta["expires_at"] = (datetime.now() + timedelta(minutes=ttl)).isoformat()
        if one_time: 
            meta["one_time"] = True
        if encrypt:
            f = Fernet(self.get_crypto_key(enc_key))
            encrypted = f.encrypt(json.dumps(message).encode()).decode()
            payload = {"_encrypted": True, "payload": encrypted}
            meta["encrypted"] = True
        
        payload["_metadata"] = meta
        
        try:
            p = Producer(self.get_conf(conf))
            p.produce(str(topic).strip(), json.dumps(payload).encode('utf-8'))
            p.flush(timeout=5.0)
            log_entry = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "topic": str(topic),
                "action": message.get("action", "custom"),
                "encrypted": "🔒" if encrypt else "",
                "message": json.dumps(payload)
            }
            st.session_state.producer_log.insert(0, log_entry)
            return True, "✓ Message sent"
        except Exception as e:
            return False, str(e)

    def fetch(self, conf, topic, count=10, dec_key=""):
        if not KAFKA_AVAILABLE: 
            return pd.DataFrame([{"error": "Library missing"}])
        try:
            c_conf = self.get_conf(conf)
            c_conf.update({
                'group.id': f'g-{int(time.time())}',
                'auto.offset.reset': 'earliest'
            })
            c = Consumer(c_conf)
            c.subscribe([str(topic).strip()])
            msgs, retries = [], 5
            while len(msgs) < count and retries > 0:
                msg = c.poll(1.0)
                if msg is None: 
                    retries -= 1
                    continue
                if msg.error(): 
                    continue
                try:
                    val = msg.value().decode('utf-8')
                    parsed = json.loads(val)
                    if "_metadata" in parsed and parsed["_metadata"].get("expires_at"):
                        if datetime.fromisoformat(parsed["_metadata"]["expires_at"]) < datetime.now():
                            continue
                    display_val = val
                    if parsed.get("_metadata", {}).get("encrypted"):
                        if not dec_key.strip():
                            display_val = "[ENCRYPTED - Enter decryption key]"
                        else:
                            try:
                                f = Fernet(self.get_crypto_key(dec_key))
                                inner = f.decrypt(parsed["payload"].encode()).decode()
                                display_val = f"[DECRYPTED] {inner}"
                            except Exception as decrypt_err:
                                display_val = f"[DECRYPTION FAILED: {str(decrypt_err)[:50]}...]"
                    msgs.append({"offset": msg.offset(), "value": display_val})
                except Exception as e:
                    msgs.append({"offset": msg.offset(), "value": f"[PARSE ERROR] {val[:50]}..."})
            c.close()
            return pd.DataFrame(msgs) if msgs else pd.DataFrame([{"info": "No messages"}])
        except Exception as e:
            return pd.DataFrame([{"error": str(e)}])

class KafkaView:
    @staticmethod
    def sidebar():
        st.sidebar.title(f"Kafka v{APP_VERSION}")
        st.sidebar.markdown("""
        ### 📚 Learning Tips
        - **Partitions**: Parallelism units  
        - **Key**: Determines partition (same key → same partition)  
        - **ISR**: In-Sync Replicas (must be ≥ replication factor)  
        - **Acks=all**: Safest delivery guarantee
        """)
        return st.sidebar.radio("Navigate", ["1. Configuration", "2. Topic CRUD", "3. Producer", "4. Consumer"])

    @staticmethod
    def config(model):
        st.header("⚙️ Configuration")
        active = st.session_state.get("active_conf", {})
        
        broker = st.text_input("Broker", value=active.get("broker", "localhost:9092"))
        cid = st.text_input("Client ID", value=active.get("client_id", "streamlit-app"))
        sec_options = ["PLAINTEXT", "SASL_PLAINTEXT", "SASL_SSL", "SASL_LDAP"]
        sec_index = sec_options.index(active.get("security", "PLAINTEXT"))
        sec = st.selectbox("Security", sec_options, index=sec_index)
        
        user, pw, ssl_ca, ssl_verify = "", "", "", True
        if sec in ["SASL_PLAINTEXT", "SASL_SSL", "SASL_LDAP"]:
            col1, col2 = st.columns(2)
            user = col1.text_input("Username", value=active.get("sasl_user", "admin"))
            pw = col2.text_input("Password", type="password")
            if not pw and active.get("sasl_pass"):
                st.caption("Using saved password")
                pw = active["sasl_pass"]

            if sec in ["SASL_SSL", "SASL_LDAP"]:
                st.caption("🔒 SSL/TLS Settings")
                
                host_ca_path = st.text_input(
                    "CA Certificate Host Path",
                    value=active.get("ssl_ca_host", ""),
                    help="Absolute path on host machine (e.g., /etc/kafka/ca.pem)"
                )
                
                uploaded_ca = st.file_uploader(
                    "Upload CA Certificate (PEM)",
                    type=["pem", "crt", "cert"],
                    help="Upload your CA certificate file"
                )
                
                pasted_ca = st.text_area(
                    "Or paste CA Certificate (PEM)",
                    value="",
                    height=100,
                    help="Paste full PEM content including -----BEGIN CERTIFICATE-----"
                )
                
                ssl_ca = ""
                if host_ca_path.strip() and os.path.exists(host_ca_path.strip()):
                    ssl_ca = host_ca_path.strip()
                elif uploaded_ca is not None:
                    ssl_ca = model.save_uploaded_ca(uploaded_ca)
                elif pasted_ca.strip():
                    ssl_ca = model.save_pasted_ca(pasted_ca)
                elif active.get("ssl_ca") and os.path.exists(active["ssl_ca"]):
                    ssl_ca = active["ssl_ca"]
                
                ssl_verify = st.checkbox(
                    "Enable SSL Certificate Verification",
                    value=active.get("ssl_verify", True),
                    help="Disable only for testing with self-signed certs!"
                )
            
            # LDAP Info
            if sec == "SASL_LDAP":
                st.info("""
                **LDAP Integration**: Kafka uses SASL/PLAIN with external LDAP authentication.
                Configure JAAS login module on Kafka server to validate against LDAP.
                """)
        
        if st.button("🔌 Test Connection"):
            with st.spinner("Testing..."):
                ok, msg = model.test_connection(broker, cid, sec, user, pw, ssl_ca, ssl_verify)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)
        
        st.divider()
        pwd = st.text_input("Master Password (encryption)", type="password")
        col1, col2 = st.columns(2)
        if col1.button("💾 Save") and pwd:
            save_data = {
                "broker": broker,
                "client_id": cid,
                "security": sec,
                "sasl_user": user,
                "sasl_pass": pw
            }
            if sec in ["SASL_SSL", "SASL_LDAP"]:
                save_data.update({
                    "ssl_ca": ssl_ca,
                    "ssl_ca_host": host_ca_path,
                    "ssl_verify": ssl_verify
                })
            model.save_config(pwd, save_data)
            st.session_state.active_conf = save_data
            st.success("✓ Configuration saved")
            st.rerun()
        if col2.button("📂 Load") and pwd:
            res = model.load_config(pwd)
            if res == "AUTH_ERROR":
                st.error("✗ Incorrect password")
            elif res:
                st.session_state.active_conf = res
                st.success(f"✓ Loaded config for {res.get('broker')}")
                st.rerun()
            else:
                st.warning("No saved configuration found")
        
        if st.session_state.get("active_conf"):
            cfg = st.session_state.active_conf
            status = f"🟢 Active: {cfg['broker']} | {cfg['security']}"
            if cfg['security'] in ['SASL_PLAINTEXT', 'SASL_SSL', 'SASL_LDAP']:
                status += f" | User: {cfg['sasl_user']}"
                if cfg['security'] in ['SASL_SSL', 'SASL_LDAP']:
                    ca_display = cfg.get('ssl_ca_host', cfg.get('ssl_ca', ''))
                    if ca_display:
                        status += f" | CA: {os.path.basename(ca_display)}"
                    status += f" | SSL Verify: {'On' if cfg.get('ssl_verify', True) else 'Off'}"
            st.info(status)

    @staticmethod
    def topic_crud(model, conf):
        st.header("🛠 Topic CRUD")
        if not conf:
            st.error("❌ Configure connection first in '1. Configuration' tab")
            st.stop()
        
        with st.spinner("Loading topics..."):
            topics = model.list_topics(conf)
        
        with st.expander("🆕 Create New Topic"):
            with st.form("create_topic"):
                col1, col2, col3 = st.columns(3)
                name = col1.text_input("Topic name")
                parts = col2.number_input("Partitions", 1, 10, 1)
                reps = col3.number_input("Replicas", 1, 3, 1)
                if st.form_submit_button("✅ Create Topic") and name.strip():
                    ok, msg = model.create_topic(conf, name, parts, reps)
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)
                    if ok:
                        time.sleep(1)
                        st.rerun()
        
        st.divider()
        
        if not topics:
            st.warning("📭 No topics found (or connection failed)")
            if st.button("🔄 Refresh Topics"):
                st.rerun()
            return
        
        st.subheader(f"📚 Topics ({len(topics)})")
        for topic in topics:
            with st.expander(f"📦 {topic}"):
                details = model.get_details(conf, topic)
                curr_parts = len(details) if isinstance(details, pd.DataFrame) else 1
                if isinstance(details, pd.DataFrame):
                    st.dataframe(details, width='stretch', hide_index=True)
                
                st.caption("⚠️ Kafka only supports INCREASING partitions")
                col1, col2 = st.columns([3, 1])
                new_parts = col1.number_input(
                    "New partition count", 
                    min_value=curr_parts + 1, 
                    max_value=20, 
                    value=curr_parts + 1,
                    key=f"part_{topic}"
                )
                if col2.button("⬆️ Increase", key=f"upd_{topic}"):
                    ok, msg = model.update_partitions(conf, topic, int(new_parts))
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)
                
                if st.button("🗑️ DELETE TOPIC", type="primary", key=f"del_{topic}"):
                    ok, msg = model.delete_topic(conf, topic)
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)
                    if ok:
                        time.sleep(1)
                        st.rerun()

    @staticmethod
    def producer(model, conf):
        st.header("📤 Message Producer")
        topics = model.list_topics(conf)
        if not topics:
            st.warning("📭 No topics available. Create one in 'Topic CRUD' tab first.")
            return
        
        with st.expander("🎓 How Partitioning Works"):
            st.markdown("""
            - Messages **without a key** are distributed round-robin across partitions.
            - Messages **with the same key** always go to the **same partition**.
            - Use keys to ensure ordering for a specific entity (e.g., user_id).
            """)
        
        # 🔑 Encryption toggle - OUTSIDE form for immediate response
        encrypt = st.checkbox("🔐 Encrypt Message?")
        enc_key = ""
        if encrypt:
            enc_key = st.text_input("Encryption Key", type="password", 
                                  help="Key used to encrypt the message payload")
        
        # Message type selection
        msg_type = st.radio("Message Type", ["Standard", "Custom JSON"], horizontal=True)
        
        with st.form("producer_form"):
            topic = st.selectbox("Topic", topics)
            
            if msg_type == "Standard":
                col1, col2 = st.columns(2)
                uid = col1.text_input("User ID", "user_123")
                action = col2.selectbox("Action", model.valid_actions)
                key = st.text_input("Message Key (optional)", help="Determines partition")
                ttl = st.number_input("TTL (minutes)", 0, 60, 0)
                
                payload = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "user_id": uid,
                    "action": action
                }
                
            else:  # Custom JSON
                st.subheader("Custom Message")
                custom_json = st.text_area(
                    "Message JSON",
                    value='{\n  "custom_field": "value",\n  "timestamp": "' + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '"\n}',
                    height=150,
                    help="Enter valid JSON. Timestamp will be auto-added if missing."
                )
                key = st.text_input("Message Key (optional)", help="Determines partition")
                
                try:
                    payload = json.loads(custom_json)
                    if "timestamp" not in payload:
                        payload["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                except json.JSONDecodeError:
                    payload = None
            
            if st.form_submit_button("📤 Send Message"):
                if msg_type == "Custom JSON" and payload is None:
                    st.error("❌ Invalid JSON format")
                elif payload:
                    if key:
                        partition_count = len(model.get_details(conf, topic)) if model.get_details(conf, topic) is not None else 1
                        partition = hash(key) % max(1, partition_count)
                        st.info(f"🔑 Key '{key}' → Partition {partition}")
                    
                    ok, msg = model.produce(conf, topic, payload, ttl if msg_type == "Standard" else 0, False, encrypt, enc_key)
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)
                else:
                    st.error("❌ Missing required fields")
        
        if st.session_state.producer_log:
            st.subheader("📜 Recent Messages")
            log_df = pd.DataFrame(st.session_state.producer_log[:10])
            st.dataframe(log_df, width='stretch', hide_index=True)

    @staticmethod
    def consumer(model, conf):
        st.header("📥 Consumer")
        topics = model.list_topics(conf)
        if not topics:
            st.warning("📭 No topics available")
            return
        
        mode = st.radio("Mode", ["Active Fetch", "Live Stream"], horizontal=True)
        topic = st.selectbox("Topic", topics)
        
        with st.expander("ℹ️ Message Format Guide"):
            st.markdown("""
            - **Raw messages**: Full JSON including `_metadata`
            - **Encrypted**: Shows `[ENCRYPTED - KEY NEEDED]` without key
            - **Decrypted**: Shows `[DECRYPTED] {...}` with correct key
            - **Expired**: Messages past TTL are automatically skipped
            """)
        
        if mode == "Active Fetch":
            col1, col2 = st.columns([1, 3])
            count = col1.number_input("Messages", 1, 20, 5)
            decrypt = col2.checkbox("🔐 Decrypt Messages?")
            dec_key = ""
            if decrypt:
                dec_key = st.text_input("Decryption Key", type="password", key="dec_key_fetch")
            
            if st.button("📥 Fetch Messages"):
                df = model.fetch(conf, topic, count, dec_key)
                if "error" in df.columns:
                    st.error(df.iloc[0]["error"])
                elif "info" in df.columns:
                    st.info(df.iloc[0]["info"])
                else:
                    st.dataframe(df, width='stretch', hide_index=True)
        else:
            st.info("⚠️ Stream runs until page refresh")
            decrypt = st.checkbox("🔐 Decrypt Messages (Stream)?")
            dec_key = ""
            if decrypt:
                dec_key = st.text_input("Decryption Key", type="password", key="dec_key_stream")
            
            if st.button("▶️ Start Stream"):
                c_conf = model.get_conf(conf)
                c_conf.update({
                    'group.id': f'stream-{int(time.time())}',
                    'auto.offset.reset': 'latest'
                })
                c = Consumer(c_conf)
                c.subscribe([str(topic).strip()])
                placeholder = st.empty()
                msgs = []
                try:
                    st.info("Streaming started. Refresh page to stop.")
                    while True:
                        msg = c.poll(0.5)
                        if msg and not msg.error():
                            val = msg.value().decode('utf-8')
                            try:
                                parsed = json.loads(val)
                                if parsed.get("_metadata", {}).get("encrypted"):
                                    if dec_key:
                                        try:
                                            f = Fernet(model.get_crypto_key(dec_key))
                                            inner = f.decrypt(parsed["payload"].encode()).decode()
                                            val = f"[DECRYPTED] {inner}"
                                        except:
                                            val = "[ENCRYPTED - INVALID KEY]"
                                    else:
                                        val = "[ENCRYPTED - KEY NEEDED]"
                            except:
                                pass
                            msgs.insert(0, {"offset": msg.offset(), "value": val})
                            if len(msgs) > 15:
                                msgs.pop()
                            placeholder.dataframe(
                                pd.DataFrame(msgs),
                                width='stretch',
                                hide_index=True
                            )
                except:
                    pass
                finally:
                    c.close()

def run_app():
    cleanup_old_certs()
    st.set_page_config(page_title=f"Kafka Explorer v{APP_VERSION}", layout="wide")
    if "model" not in st.session_state:
        st.session_state.model = KafkaModel()
    
    model = st.session_state.model
    page = KafkaView.sidebar()
    conf = st.session_state.get("active_conf")
    
    if page == "1. Configuration":
        KafkaView.config(model)
    elif not conf:
        st.warning("🔒 Configure connection in '1. Configuration' tab first")
    elif page == "2. Topic CRUD":
        KafkaView.topic_crud(model, conf)
    elif page == "3. Producer":
        KafkaView.producer(model, conf)
    elif page == "4. Consumer":
        KafkaView.consumer(model, conf)

def main():
    if st.runtime.exists():
        run_app()
    else:
        sys.argv = ["streamlit", "run", __file__]
        sys.exit(stcli.main())

if __name__ == "__main__":
    main()
