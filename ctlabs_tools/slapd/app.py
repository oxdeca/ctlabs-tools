# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/slapd/app.py
# License : MIT
# -----------------------------------------------------------------------------

import streamlit as st
import pandas as pd
import json
import os
import base64
import ssl
import difflib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ldap3 import Server, Connection, ALL, Tls, SUBTREE, LEVEL

# --- APP CONFIGURATION ---
st.set_page_config(page_title="LDAP Manager", layout="wide", page_icon="🛡️")
APP_VERSION = "1.5.1"
CREATED_DATE = "2023-10-27"

# ==========================================
# MODEL: Logic, Data & Encryption
# ==========================================
class LDAPModel:
    def __init__(self):
        self.config_file = "ldap_config.enc"
        
    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def save_config(self, data: dict, password: str):
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        f = Fernet(key)
        encrypted_data = f.encrypt(json.dumps(data).encode())
        with open(self.config_file, "wb") as file:
            file.write(salt + encrypted_data)

    def load_config(self, password: str) -> dict:
        if not os.path.exists(self.config_file): return {}
        try:
            with open(self.config_file, "rb") as file:
                content = file.read()
            salt, payload = content[:16], content[16:]
            key = self.derive_key(password, salt)
            f = Fernet(key)
            return json.loads(f.decrypt(payload).decode())
        except Exception: return None

    def get_connection(self, config):
        tls_ctx = None
        if config.get('use_ssl'):
            proto = ssl.PROTOCOL_TLS_CLIENT
            val = ssl.CERT_REQUIRED if config.get('verify_ssl') else ssl.CERT_NONE
            ciphers = "ALL:@SECLEVEL=0" if config.get('allow_deprecated') else None
            tls_ctx = Tls(validate=val, version=proto, ciphers=ciphers)

        server = Server(config['server'], use_ssl=config.get('use_ssl', False), 
                        tls=tls_ctx, get_info=ALL, connect_timeout=10)
        
        user = None if config.get('anonymous') else config.get('user')
        pwd = None if config.get('anonymous') else config.get('password')
        return Connection(server, user=user, password=pwd, auto_bind=True)

    def _safe_encode_value(self, val):
        if isinstance(val, bytes):
            try: return val.decode('utf-8')
            except UnicodeDecodeError: return f"0x{val.hex().upper()}"
        if isinstance(val, (list, tuple)):
            return ", ".join(map(str, [self._safe_encode_value(v) for v in val]))
        return str(val) if val is not None else ""

    def fetch_search_data(self, config, search_filter="(objectClass=*)"):
        try:
            conn = self.get_connection(config)
            conn.search(config['base_dn'], search_filter, search_scope=SUBTREE, attributes=['*'])
            data = []
            for entry in conn.entries:
                raw = entry.entry_attributes_as_dict
                clean = {k: self._safe_encode_value(v) for k, v in raw.items()}
                clean['dn'] = entry.entry_dn
                data.append(clean)
            conn.unbind()
            return pd.DataFrame(data).astype(str)
        except Exception as e:
            st.error(f"Search Error: {e}")
            return pd.DataFrame()

    def fetch_tree_node(self, config, target_dn):
        try:
            conn = self.get_connection(config)
            conn.search(target_dn, '(objectClass=*)', search_scope=LEVEL, attributes=['*'])
            children = []
            for entry in conn.entries:
                raw = entry.entry_attributes_as_dict
                clean = {k: self._safe_encode_value(v) for k, v in raw.items()}
                clean['dn'] = entry.entry_dn
                
                oc = clean.get('objectClass', '').lower()
                if any(x in oc for x in ['organizationalunit', 'container', 'domain', 'builtindomain']):
                    clean['type'] = 'container'
                elif 'person' in oc or 'user' in oc:
                    clean['type'] = 'user'
                elif 'group' in oc:
                    clean['type'] = 'group'
                elif 'computer' in oc:
                    clean['type'] = 'computer'
                else:
                    clean['type'] = 'file'
                    
                children.append(clean)
            conn.unbind()
            return pd.DataFrame(children).astype(str)
        except Exception as e:
            st.error(f"Tree Error: {e}")
            return pd.DataFrame()

    def generate_unified_diff(self, obj_a, obj_b):
        json_a = json.dumps(obj_a, indent=2, sort_keys=True).splitlines()
        json_b = json.dumps(obj_b, indent=2, sort_keys=True).splitlines()
        
        diff = difflib.unified_diff(
            json_a, json_b, 
            fromfile='Reference', tofile='Target', 
            lineterm=''
        )
        return "\n".join(diff)

    def generate_dot_graph(self, df, base_dn):
        if df.empty or 'dn' not in df.columns: return None
        edges = set(); nodes = set(); found_dns = set(df['dn'].unique())
        
        def get_parent(dn):
            parts = dn.split(',', 1)
            return parts[1].strip() if len(parts) > 1 else None

        all_nodes = set(found_dns)
        for dn in found_dns:
            curr = dn
            while curr:
                all_nodes.add(curr)
                if curr.lower() == base_dn.lower(): break
                parent = get_parent(curr)
                if parent:
                    edges.add((parent, curr))
                    curr = parent
                else: break
        
        dot = [
            'digraph G {', 'bgcolor="transparent";', 'rankdir=LR;', 'splines=ortho;', 
            'nodesep=0.4;', 'ranksep=1.0;',
            'node [shape=box, style="rounded,filled", fontname="Segoe UI, Helvetica, Arial", fontsize=10, penwidth=1.5, margin=0.2];',
            'edge [color="#90A4AE", penwidth=1.2, arrowsize=0.7];'
        ]
        
        for n in all_nodes:
            is_result = n in found_dns
            label = n.split(',')[0]
            if len(label) > 25: label = label[:22] + "..."
            if is_result: fill, border, font = "#E1F5FE", "#0288D1", "#01579B"
            else: fill, border, font = "#F5F5F5", "#BDBDBD", "#616161"
            dot.append(f'  "{n}" [label="{label}", fillcolor="{fill}", color="{border}", fontcolor="{font}"];')
        
        for p, c in edges: dot.append(f'  "{p}" -> "{c}";')
        dot.append('}')
        return "\n".join(dot)

# ==========================================
# VIEW: UI Rendering
# ==========================================
class LDAPView:
    @staticmethod
    def sidebar():
        st.sidebar.title("LDAP Manager")
        nav = st.sidebar.radio("Navigation", ["Search & Edit", "Tree Browser", "Configuration", "Import/Export"])
        st.sidebar.divider()
        st.sidebar.caption(f"v{APP_VERSION} | {CREATED_DATE}")
        return nav

    @staticmethod
    def get_icon(obj_type):
        return {'container': '📁', 'user': '👤', 'group': '👥', 'computer': '💻', 'file': '📄'}.get(obj_type, '📄')

    @staticmethod
    def render_config(existing):
        st.header("⚙️ Configuration")
        with st.form("config_form"):
            c1, c2 = st.columns(2)
            srv = c1.text_input("Server", existing.get('server', ''))
            base = c1.text_input("Root DN", existing.get('base_dn', ''))
            anon = c1.checkbox("Anonymous", existing.get('anonymous', False))
            usr = c2.text_input("User DN", existing.get('user', ''), disabled=anon)
            pwd = c2.text_input("Password", existing.get('password', ''), type="password", disabled=anon)
            st.divider()
            s1, s2, s3 = st.columns(3)
            use_ssl = s1.checkbox("Use SSL", existing.get('use_ssl', False))
            v_ssl = s2.checkbox("Verify Cert", existing.get('verify_ssl', True))
            dep = s3.checkbox("Legacy Ciphers", existing.get('allow_deprecated', False))
            mst = st.text_input("Encryption Password (Required to Save)", type="password")
            b_save = st.form_submit_button("Save Config")
            b_test = st.form_submit_button("Test Connection")
            cfg = {"server":srv, "base_dn":base, "anonymous":anon, "user":usr, "password":pwd, 
                   "use_ssl":use_ssl, "verify_ssl":v_ssl, "allow_deprecated":dep}
            return b_save, b_test, cfg, mst

    @staticmethod
    def render_diff_view(obj_a, obj_b, model):
        with st.expander("⚖️ Comparison Results", expanded=True):
            diff_text = model.generate_unified_diff(obj_a, obj_b)
            st.code(diff_text, language="diff")
            st.divider()
            c1, c2 = st.columns(2)
            with c1:
                st.subheader("Reference (Object A)")
                st.caption(obj_a.get('dn'))
                st.json(obj_a)
            with c2:
                st.subheader("Target (Object B)")
                st.caption(obj_b.get('dn'))
                st.json(obj_b)

    @staticmethod
    def render_search_browser(df, model, config):
        st.header("🔎 Search & Edit")
        if df.empty: st.info("No data."); return

        # --- COMPARISON RESULTS (Persistent) ---
        if st.session_state.get('diff_data'):
            LDAPView.render_diff_view(st.session_state['diff_data'][0], st.session_state['diff_data'][1], model)
            if st.button("Clear Results"):
                st.session_state['diff_data'] = None
                st.rerun()
            st.divider()

        # FILTERS
        with st.expander("Filters", expanded=True):
            c1, c2, c3 = st.columns(3)
            all_classes = sorted(list({p.strip() for s in df['objectClass'].unique() for p in s.split(", ")})) if 'objectClass' in df.columns else []
            sel_class = c1.multiselect("Object Class", ["All"] + all_classes, default="All")
            temp_df = df.copy()
            if "All" not in sel_class and sel_class:
                temp_df = temp_df[temp_df['objectClass'].str.contains('|'.join(sel_class), case=False, na=False)]
            name_col = next((c for c in ['cn', 'name', 'sAMAccountName'] if c in temp_df.columns), None)
            if name_col:
                all_names = sorted(temp_df[name_col].unique())
                sel_names = c2.multiselect(f"Filter {name_col}", ["All"] + all_names, default="All")
                if "All" not in sel_names and sel_names: temp_df = temp_df[temp_df[name_col].isin(sel_names)]
            txt = c3.text_input("Text Search", "")
            if txt: temp_df = temp_df[temp_df.apply(lambda row: row.str.contains(txt, case=False).any(), axis=1)]

        # GRAPH
        with st.expander("🕸️ Hierarchy Visualization"):
            if 0 < len(temp_df) <= 60:
                dot = model.generate_dot_graph(temp_df, config.get('base_dn', ''))
                if dot: st.graphviz_chart(dot, use_container_width=True)
            elif len(temp_df) > 60: st.caption("Filter < 60 items to visualize.")

        st.subheader("Results")
        
        # --- MODE TOGGLE LOGIC ---
        # 1. Get current index from state
        current_index = st.session_state.get('search_mode_index', 0)
        
        # 2. Render radio button (NOT bound to a fixed key that we overwrite)
        # We allow the user to change it, and we update the state manually.
        mode_label = st.radio("Mode", ["Browse/Edit", "Compare"], index=current_index, horizontal=True)
        
        # 3. Update state based on user selection
        new_index = 0 if mode_label == "Browse/Edit" else 1
        if new_index != current_index:
            st.session_state['search_mode_index'] = new_index
            st.rerun()

        if mode_label == "Compare":
            st.info("Check exactly 2 boxes below to compare.")
            comp_df = temp_df.copy()
            comp_df.insert(0, "Select", False)
            
            with st.form("search_compare_form"):
                edited = st.data_editor(
                    comp_df, use_container_width=True, hide_index=True,
                    column_config={"Select": st.column_config.CheckboxColumn(required=True)},
                    disabled=[c for c in comp_df.columns if c != "Select"]
                )
                if st.form_submit_button("Run Comparison"):
                    selected_rows = edited[edited["Select"]]
                    if len(selected_rows) == 2:
                        # Save result
                        obj_a = selected_rows.iloc[0].drop("Select").to_dict()
                        obj_b = selected_rows.iloc[1].drop("Select").to_dict()
                        st.session_state['diff_data'] = (obj_a, obj_b)
                        
                        # --- THE FIX: RESET MODE PROGRAMMATICALLY ---
                        st.session_state['search_mode_index'] = 0 
                        st.rerun()
                    else:
                        st.error(f"Select exactly 2 rows. (Selected: {len(selected_rows)})")
        else:
            # Browse Mode
            if st.checkbox("Enable Edit Mode"):
                with st.form("edit_form"):
                    edited = st.data_editor(temp_df, use_container_width=True, hide_index=True)
                    if st.form_submit_button("Store Changes"):
                        st.session_state['current_data'].update(edited)
                        st.rerun()
            else:
                event = st.dataframe(temp_df, use_container_width=True, hide_index=True, 
                                     on_select="rerun", selection_mode="single-row")
                if event.selection.rows:
                    st.divider()
                    st.subheader("📄 Details")
                    st.json(temp_df.iloc[event.selection.rows[0]].to_dict())

    @staticmethod
    def render_tree_browser(df, current_dn, root_dn, model):
        st.header("🌳 Tree Browser")
        parts = [p.strip() for p in current_dn.split(',') if p.strip()]
        with st.container():
            cols = st.columns([1] + [2] * len(parts))
            if cols[0].button("🏠", help="Root"): return "GOTO", root_dn, None
            for i, part in enumerate(parts):
                if cols[i+1].button(part, key=f"crumb_{i}"): return "GOTO", ",".join(parts[i:]), None
        st.divider()

        if df.empty: st.warning("Empty."); return None, None, None

        if st.session_state.get('tree_diff_data'):
            LDAPView.render_diff_view(st.session_state['tree_diff_data'][0], st.session_state['tree_diff_data'][1], model)
            if st.button("Close Tree Comparison"):
                st.session_state['tree_diff_data'] = None
                st.rerun()
            st.divider()

        compare_active = st.checkbox("Enable Comparison Mode", key="tree_compare_toggle")
        
        if compare_active:
            comp_df = df[['type', 'dn', 'objectClass']].copy()
            comp_df.insert(0, "Select", False)
            with st.form("tree_compare_form"):
                edited = st.data_editor(
                    comp_df, use_container_width=True, hide_index=True,
                    column_config={"Select": st.column_config.CheckboxColumn(required=True)},
                    disabled=["type", "dn", "objectClass"]
                )
                if st.form_submit_button("Run Comparison"):
                    selected_rows = edited[edited["Select"]]
                    if len(selected_rows) == 2:
                        full_a = df[df['dn'] == selected_rows.iloc[0]['dn']].iloc[0].to_dict()
                        full_b = df[df['dn'] == selected_rows.iloc[1]['dn']].iloc[0].to_dict()
                        st.session_state['tree_diff_data'] = (full_a, full_b)
                        # Optional: Close toggle automatically? 
                        # st.session_state['tree_compare_toggle'] = False # This works because checkbox is key-bound
                        st.rerun()
                    else: st.error("Select exactly 2 rows.")
            return None, None, None

        t1, t2 = st.tabs(["📁 Grid", "📋 List"])
        selected_obj = None; action = None; target = None

        with t1:
            cols_per_row = 4
            for i in range(0, len(df), cols_per_row):
                row_items = df.iloc[i:i + cols_per_row]
                cols = st.columns(cols_per_row)
                for idx, (_, item) in enumerate(row_items.iterrows()):
                    with cols[idx]:
                        icon = LDAPView.get_icon(item['type'])
                        name = (item.get('cn', item.get('name', 'Object'))[:15] + '..')
                        if st.button(f"{icon}\n{name}", key=f"grid_{item['dn']}", use_container_width=True):
                            if item['type'] == 'container': return "GOTO", item['dn'], None
                            else: return "SELECT", None, item.to_dict()
        with t2:
            event = st.dataframe(df[['type', 'dn', 'objectClass']], use_container_width=True, hide_index=True, on_select="rerun", selection_mode="single-row")
            if event.selection.rows:
                obj = df.iloc[event.selection.rows[0]].to_dict()
                if obj['type'] == 'container':
                    if st.button(f"Open {obj.get('cn')}", key="lst_op"): return "GOTO", obj['dn'], None
                return "SELECT", None, obj
        return action, target, selected_obj

# ==========================================
# CONTROLLER
# ==========================================
class LDAPController:
    def __init__(self):
        self.model = LDAPModel()
        self.view = LDAPView()
        if 'config' not in st.session_state: st.session_state['config'] = {}
        if 'current_data' not in st.session_state: st.session_state['current_data'] = pd.DataFrame()
        if 'tree_data' not in st.session_state: st.session_state['tree_data'] = pd.DataFrame()
        if 'current_dn' not in st.session_state: st.session_state['current_dn'] = ""
        if 'selected_node' not in st.session_state: st.session_state['selected_node'] = None
        if 'diff_data' not in st.session_state: st.session_state['diff_data'] = None
        if 'tree_diff_data' not in st.session_state: st.session_state['tree_diff_data'] = None
        if 'search_mode_index' not in st.session_state: st.session_state['search_mode_index'] = 0

    def run(self):
        page = self.view.sidebar()

        if page == "Configuration":
            with st.expander("Unlock Configuration"):
                lpwd = st.text_input("Master Password", type="password")
                if st.button("Load"):
                    cfg = self.model.load_config(lpwd)
                    if cfg:
                        st.session_state['config'] = cfg
                        st.session_state['current_dn'] = cfg.get('base_dn', "")
                        st.rerun()
                    else: st.error("Decrypt failed.")
            save, test, cfg, pwd = self.view.render_config(st.session_state['config'])
            if test:
                try:
                    conn = self.model.get_connection(cfg)
                    if conn.bound: st.success("Connected!"); conn.unbind()
                except Exception as e: st.error(f"Error: {e}")
            if save:
                if pwd: self.model.save_config(cfg, pwd); st.session_state['config'] = cfg; st.success("Saved.")
                else: st.error("Password required.")

        elif page == "Search & Edit":
            if st.button("🔄 Sync All"):
                if st.session_state['config']:
                    st.session_state['current_data'] = self.model.fetch_search_data(st.session_state['config'])
                    st.rerun()
            self.view.render_search_browser(st.session_state['current_data'], self.model, st.session_state['config'])

        elif page == "Tree Browser":
            if not st.session_state['config']: st.warning("Configure first.")
            else:
                if st.session_state['tree_data'].empty or not st.session_state['current_dn']:
                    st.session_state['current_dn'] = st.session_state['config'].get('base_dn', "")
                    st.session_state['tree_data'] = self.model.fetch_tree_node(st.session_state['config'], st.session_state['current_dn'])

                act, target, node = self.view.render_tree_browser(st.session_state['tree_data'], st.session_state['current_dn'], st.session_state['config'].get('base_dn', ""), self.model)
                
                if act == "GOTO":
                    st.session_state['current_dn'] = target
                    st.session_state['tree_data'] = self.model.fetch_tree_node(st.session_state['config'], target)
                    st.session_state['selected_node'] = None
                    st.rerun()
                elif act == "SELECT": st.session_state['selected_node'] = node
                
                if not st.session_state.get('tree_diff_data'):
                    if st.session_state['selected_node']:
                        st.divider()
                        st.subheader("📄 Object Details")
                        icon = LDAPView.get_icon(st.session_state['selected_node'].get('type','file'))
                        st.markdown(f"### {icon} {st.session_state['selected_node'].get('cn', 'Object')}")
                        st.json(st.session_state['selected_node'])

        elif page == "Import/Export":
            st.header("Import/Export")
            up = st.file_uploader("Upload", type=["json", "jsonl"])
            if up:
                try:
                    lines = up.getvalue().decode().splitlines()
                    data = [json.loads(l) for l in lines if l.strip()] if not up.name.endswith('.json') else json.loads("\n".join(lines))
                    st.session_state['current_data'] = pd.DataFrame(data).astype(str)
                    st.success("Imported!")
                except Exception as e: st.error(str(e))
            if not st.session_state['current_data'].empty:
                st.download_button("Export Search Data", st.session_state['current_data'].to_json(orient='records', indent=2).encode('utf-8'), "export.json")

if __name__ == "__main__":
    LDAPController().run()
