import streamlit as st
import pandas as pd
import io
import os
import numpy as np
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Version: 1.2.1
# Created: 2026-02-05
# Change: Restored Smallest/Biggest file size stats.
# Note: Set STREAMLIT_SERVER_MAX_UPLOAD_SIZE=512 in env or config.toml for large files.

# --- MODEL ---
class FileModel:
    def __init__(self):
        self.data = pd.DataFrame()
        self.config = {}

    def parse_ls_output_fast(self, text):
        try:
            # Vectorized parsing for 512MB+ files
            df = pd.read_csv(
                io.StringIO(text), 
                sep=r'\s+', 
                header=None, 
                on_bad_lines='skip',
                engine='c'
            )
            if df.shape[1] >= 9:
                # Columns: Perms(0), Links(1), Owner(2), Group(3), Size(4), Month(5), Day(6), Time(7), Name(8)
                df = df.iloc[:, [0, 2, 3, 4, 8]]
                df.columns = ['Permissions', 'Owner', 'Group', 'Size', 'Name']
                df['Size'] = pd.to_numeric(df['Size'], errors='coerce')
                self.data = df.dropna(subset=['Size'])
            return self.data
        except Exception as e:
            st.error(f"Error parsing file: {e}")
            return pd.DataFrame()

    def get_size_bins(self, df):
        if df.empty: return pd.DataFrame()
        
        bins = [0, 512, 1024, 1024**2, 100*1024**2, 1024**3, np.inf]
        labels = ['0-512B', '512B-1KB', '1KB-1MB', '1MB-100MB', '100MB-1GB', '>1GB']
        
        counts = pd.cut(df['Size'], bins=bins, labels=labels, right=False).value_counts().sort_index()
        return pd.DataFrame({'Size Range': counts.index, 'File Count': counts.values})

    def get_statistics(self, df):
        if df.empty: return {}
        return {
            "Total Files": f"{len(df):,}",
            "Smallest": f"{df['Size'].min():,} B",
            "Average": f"{(df['Size'].mean() / 1024):.2f} KB",
            "Largest": f"{df['Size'].max():,} B",
            "Total Size": f"{(df['Size'].sum() / (1024**3)):.2f} GB"
        }

    def encrypt_data(self, data_dict, password):
        salt = b'static_salt_fixed' 
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        return f.encrypt(json.dumps(data_dict).encode())

    def decrypt_data(self, token, password):
        salt = b'static_salt_fixed'
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        return json.loads(f.decrypt(token).decode())

# --- CONTROLLER ---
class AppController:
    def __init__(self, model):
        self.model = model

    def handle_upload(self, uploaded_file):
        content = uploaded_file.read().decode("utf-8")
        with st.spinner("Parsing large dataset..."):
            return self.model.parse_ls_output_fast(content)

    def save_config(self, config, password):
        try:
            encrypted = self.model.encrypt_data(config, password)
            # In a real app, save to disk. Here we simulate by storing in session.
            st.session_state['saved_config_blob'] = encrypted 
            return True
        except Exception as e:
            return False

    def load_config(self, password):
        try:
            if 'saved_config_blob' in st.session_state:
                return self.model.decrypt_data(st.session_state['saved_config_blob'], password)
        except Exception:
            return None
        return None

# --- VIEW ---
def main():
    st.set_page_config(layout="wide", page_title="ls -l Analyzer v1.2.1")
    
    if 'model' not in st.session_state:
        st.session_state.model = FileModel()
    if 'controller' not in st.session_state:
        st.session_state.controller = AppController(st.session_state.model)
    if 'edit_mode' not in st.session_state:
        st.session_state.edit_mode = False

    st.title("🛡️ Secure File Analyzer")
    
    tab_analysis, tab_config = st.tabs(["Analysis", "Configuration"])

    # --- TAB: ANALYSIS ---
    with tab_analysis:
        uploaded_file = st.file_uploader("Upload 'ls -l' output", type=['txt', 'json', 'jsonl'])
        
        if uploaded_file:
            if 'raw_data' not in st.session_state or st.button("Reload File"):
                st.session_state.raw_data = st.session_state.controller.handle_upload(uploaded_file)
            
            df = st.session_state.raw_data

            # --- SEARCH FILTER FORM ---
            with st.form("filter_form"):
                st.subheader("Filter Data")
                c1, c2 = st.columns(2)
                
                owners = ["All"] + sorted(df['Owner'].unique().tolist())
                selected_owner = c1.selectbox("Owner", owners)
                
                # Cascading Filter Logic
                if selected_owner != "All":
                    filtered_groups = df[df['Owner'] == selected_owner]['Group'].unique()
                else:
                    filtered_groups = df['Group'].unique()
                
                selected_group = c2.selectbox("Group", ["All"] + sorted(filtered_groups.tolist()))
                
                col_sub, col_res = st.columns([1, 10])
                submit = col_sub.form_submit_button("Apply Filters")
                reset = col_res.form_submit_button("Reset All")

            if reset:
                st.rerun()

            # Filter Application
            display_df = df.copy()
            if selected_owner != "All":
                display_df = display_df[display_df['Owner'] == selected_owner]
            if selected_group != "All":
                display_df = display_df[display_df['Group'] == selected_group]

            # --- STATISTICS ---
            st.divider()
            stats = st.session_state.model.get_statistics(display_df)
            cols = st.columns(len(stats))
            for i, (k, v) in enumerate(stats.items()):
                cols[i].metric(k, v)

            # --- SIZE DISTRIBUTION (BINS) ---
            st.subheader("File Size Distribution")
            bin_df = st.session_state.model.get_size_bins(display_df)
            c_chart, c_table = st.columns([2, 1])
            with c_chart:
                st.bar_chart(bin_df, x='Size Range', y='File Count', width='stretch')
            with c_table:
                st.dataframe(bin_df, width='stretch')

            # --- EDITABLE TABLE ---
            st.divider()
            st.subheader("File Details")
            if st.button("Toggle Edit Mode"):
                st.session_state.edit_mode = not st.session_state.edit_mode

            if st.session_state.edit_mode:
                with st.form("edit_form"):
                    edited_df = st.data_editor(display_df.head(1000), width='stretch')
                    if st.form_submit_button("Save Changes"):
                        st.session_state.raw_data.update(edited_df)
                        st.success("Changes saved to memory.")
            else:
                st.dataframe(display_df.head(1000), width='stretch')

    # --- TAB: CONFIGURATION ---
    with tab_config:
        st.header("Encrypted Configuration")
        with st.form("config_form"):
            password = st.text_input("Password", type="password")
            theme = st.selectbox("Theme", ["Light", "Dark", "System"])
            max_rows = st.number_input("Max Rows to Display", value=1000)
            
            c_save, c_load = st.columns(2)
            save_btn = c_save.form_submit_button("Save Config")
            load_btn = c_load.form_submit_button("Load Config")

            if save_btn and password:
                if st.session_state.controller.save_config({"theme": theme, "rows": max_rows}, password):
                    st.success("Configuration encrypted and saved.")
            
            if load_btn and password:
                loaded = st.session_state.controller.load_config(password)
                if loaded:
                    st.json(loaded)
                else:
                    st.error("Invalid password or no config found.")

if __name__ == "__main__":
    main()
