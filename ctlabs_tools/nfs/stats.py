# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/nfs/stats.py
# License : MIT
# -----------------------------------------------------------------------------

import streamlit as st
import pandas as pd
import json
import base64
import os
import re
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- VERSION INFO ---
# Version: 1.2.0 (Fix: nfsstat multi-line parsing)
# Created: 2026-02-05
# --------------------

# ==========================================
# MODEL: Data Handling & Logic
# ==========================================
class AppModel:
    def __init__(self):
        if "data" not in st.session_state:
            # Columns adjusted for generic import
            st.session_state.data = pd.DataFrame(columns=["Category", "Attribute", "Value", "Percentage"])
        if "config" not in st.session_state:
            st.session_state.config = {"API_KEY": "", "ENDPOINT": "", "THEME": "Light"}
            
    def derive_key(self, password: str) -> bytes:
        salt = b'static_salt_for_demo' # In production, use a unique stored salt
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_config(self, password: str):
        key = self.derive_key(password)
        f = Fernet(key)
        data = json.dumps(st.session_state.config).encode()
        return f.encrypt(data)

    def decrypt_config(self, password: str, encrypted_data: bytes):
        try:
            key = self.derive_key(password)
            f = Fernet(key)
            decrypted = f.decrypt(encrypted_data)
            st.session_state.config = json.loads(decrypted.decode())
            return True
        except Exception:
            return False

    def load_json_files(self, uploaded_file):
        # Supports .json, .jsonl, .jsond
        if uploaded_file.name.endswith(('.jsonl', '.jsond')):
            lines = uploaded_file.getvalue().decode("utf-16" if "utf-16" in uploaded_file.name else "utf-8").splitlines()
            data = [json.loads(line) for line in lines]
        else:
            data = json.load(uploaded_file)
        st.session_state.data = pd.DataFrame(data)

    def parse_nfsstat(self, raw_text: str):
        """
        Parses nfsstat -3 output where headers are on one line and values on the next.
        Handles optional percentages interleaved in values.
        """
        lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
        records = []
        current_category = "General"
        
        # Buffer to hold the previous line which might be headers
        header_candidates = []
        
        for i, line in enumerate(lines):
            # 1. Detect Category Section
            if line.endswith(":"):
                current_category = line.replace(":", "").strip()
                header_candidates = [] # Reset headers on new section
                continue
            
            # 2. Tokenize the line
            tokens = line.split()
            
            # 3. Heuristic: If line is all numbers (or numbers+%), it's DATA. 
            #    The previous line must be HEADERS.
            is_data_line = False
            try:
                # Check if first token is a digit
                if tokens and tokens[0][0].isdigit():
                    is_data_line = True
            except:
                pass

            if is_data_line and header_candidates:
                headers = header_candidates
                
                # Logic to align Headers with Data (skipping percentages)
                data_values = []
                data_percents = []
                
                # Iterate through tokens to separate Values from Percentages
                temp_val = None
                for token in tokens:
                    if token.endswith('%'):
                        # It's a percentage for the *previous* value
                        if data_percents: 
                            data_percents[-1] = token
                    else:
                        # It's a value
                        data_values.append(token)
                        data_percents.append("0%") # Default if no % follows
                
                # Zip headers with cleaned values
                for h, v, p in zip(headers, data_values, data_percents):
                    records.append({
                        "Category": current_category,
                        "Attribute": h,
                        "Value": v, # Store as string initially to prevent int errors
                        "Percentage": p
                    })
                
                # Clear headers after using them
                header_candidates = []
                
            else:
                # If not data, assume it's a header line for the *next* line
                # We filter out purely structural words if necessary, but nfsstat headers are clean
                header_candidates = tokens

        if records:
            # Convert Value to numeric where possible
            df = pd.DataFrame(records)
            df['Value'] = pd.to_numeric(df['Value'], errors='ignore')
            st.session_state.data = df
            return True
        return False

# ==========================================
# VIEW: UI Components
# ==========================================
class AppView:
    @staticmethod
    def render_sidebar():
        st.sidebar.title("Navigation")
        return st.sidebar.radio("Go to", ["Dashboard", "Configuration", "Data Import"])

    @staticmethod
    def render_config_view(controller):
        st.header("Settings & Encryption")
        with st.expander("Encryption Controls", expanded=True):
            pwd = st.text_input("Vault Password", type="password")
            col1, col2 = st.columns(2)
            if col1.button("Save Encrypted Config", use_container_width=True):
                controller.handle_save_config(pwd)
            if col2.button("Load Encrypted Config", use_container_width=True):
                controller.handle_load_config(pwd)

        with st.form("config_form"):
            st.subheader("App Configuration")
            st.session_state.config["API_KEY"] = st.text_input("API Key", st.session_state.config.get("API_KEY", ""))
            st.session_state.config["ENDPOINT"] = st.text_input("Endpoint", st.session_state.config.get("ENDPOINT", ""))
            
            if st.form_submit_button("Update Memory State", width='stretch'):
                st.success("State updated (not yet encrypted to disk)")

    @staticmethod
    def render_filter_form(df):
        with st.form("filter_form"):
            st.subheader("Cascading Search")
            col1, col2 = st.columns(2)
            
            # Cascading Logic
            categories = ["All"] + sorted(df["Category"].astype(str).unique().tolist()) if not df.empty else ["All"]
            cat_choice = col1.selectbox("Major Section (Category)", categories)
            
            sub_options = ["All"]
            if not df.empty:
                if cat_choice != "All":
                    filtered_sub = df[df["Category"] == cat_choice]["Attribute"].unique().tolist()
                else:
                    filtered_sub = df["Attribute"].unique().tolist()
                sub_options += sorted(filtered_sub)
            
            attr_choice = col2.selectbox("Attribute", sub_options)
            
            c1, c2 = st.columns(2)
            submit = c1.form_submit_button("Apply Filters", width='stretch')
            reset = c2.form_submit_button("Reset All", width='stretch')
            
            if reset:
                return "All", "All"
            return cat_choice, attr_choice

    @staticmethod
    def render_data_editor(df):
        st.subheader("Data Management")
        edit_mode = st.toggle("Enable Edit Mode")
        
        if edit_mode:
            with st.form("data_edit_form"):
                edited_df = st.data_editor(df, width='stretch', num_rows="dynamic", use_container_width=True)
                if st.form_submit_button("Save Changes"):
                    # Update the main session state with the edited dataframe
                    # In a real app, you might merge based on ID, here we replace for simplicity
                    st.session_state.data = edited_df
                    st.success("Changes saved to session.")
                    st.rerun()
        else:
            st.dataframe(df, width='stretch', use_container_width=True)

    @staticmethod
    def render_import_view(controller):
        st.header("Data Import")
        tab1, tab2 = st.tabs(["JSON File Import", "Terminal Paste"])
        
        with tab1:
            uploaded = st.file_uploader("Upload JSON/JSONL/JSOND", type=["json", "jsonl", "jsond"])
            if uploaded:
                try:
                    controller.model.load_json_files(uploaded)
                    st.success(f"Loaded {len(st.session_state.data)} records.")
                except Exception as e:
                    st.error(f"Error loading file: {e}")

        with tab2:
            st.markdown("Paste output from: `nfsstat -3`")
            with st.form("terminal_paste"):
                raw_text = st.text_area("Terminal Output", height=300)
                if st.form_submit_button("Parse & Import", width='stretch'):
                    if controller.model.parse_nfsstat(raw_text):
                        st.success(f"Parsed {len(st.session_state.data)} metrics.")
                    else:
                        st.error("Could not parse. Ensure format matches 'nfsstat -3'.")

# ==========================================
# CONTROLLER: Orchestration
# ==========================================
class AppController:
    def __init__(self):
        self.model = AppModel()
        self.view = AppView()

    def handle_save_config(self, pwd):
        if not pwd: 
            st.error("Password required")
            return
        encrypted = self.model.encrypt_config(pwd)
        with open("config.enc", "wb") as f:
            f.write(encrypted)
        st.success("Configuration encrypted and saved to config.enc")

    def handle_load_config(self, pwd):
        if os.path.exists("config.enc"):
            with open("config.enc", "rb") as f:
                content = f.read()
            if self.model.decrypt_config(pwd, content):
                st.success("Config loaded successfully")
                st.rerun()
            else:
                st.error("Invalid Password or corrupted file")
        else:
            st.error("No config file found")

    def run(self):
        st.set_page_config(page_title="Streamlit MVC App", layout="wide")
        st.title("Streamlit MVC Framework")
        st.caption(f"v1.2.0 | {datetime.now().strftime('%Y-%m-%d')}")

        page = self.view.render_sidebar()

        if page == "Dashboard":
            df = st.session_state.data
            cat, attr = self.view.render_filter_form(df)
            
            # Filtering logic
            filtered_df = df.copy()
            if not filtered_df.empty:
                if cat != "All":
                    filtered_df = filtered_df[filtered_df["Category"] == cat]
                if attr != "All":
                    filtered_df = filtered_df[filtered_df["Attribute"] == attr]
                
            self.view.render_data_editor(filtered_df)

        elif page == "Configuration":
            self.view.render_config_view(self)

        elif page == "Data Import":
            self.view.render_import_view(self)

# --- START APP ---
if __name__ == "__main__":
    controller = AppController()
    controller.run()

