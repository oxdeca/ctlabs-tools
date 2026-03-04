# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/mixins/k8s.py
# License : MIT
# -----------------------------------------------------------------------------

class VaultK8sMixin:
    # -------------------------------------------------------------------------
    # KUBERNETES AUTH MANAGEMENT
    # -------------------------------------------------------------------------
    def create_kubernetes_role(self, name, sa_names, sa_namespaces, policies=None, ttl="1h"):
        """Creates or updates a Kubernetes Auth Role."""
        client = self._get_client()
        if not client: return False
        
        payload = {
            "bound_service_account_names": [sa.strip() for sa in sa_names.split(",")],
            "bound_service_account_namespaces": [ns.strip() for ns in sa_namespaces.split(",")],
            "token_ttl": ttl
        }
        if policies:
            payload['token_policies'] = [p.strip() for p in policies.split(",")]
            
        try:
            client.write(f"auth/kubernetes/role/{name}", **payload)
            return True
        except Exception as e:
            print(f"❌ Error creating Kubernetes role '{name}': {e}")
            return False

    def read_kubernetes_role(self, name):
        """Reads configuration details for a Kubernetes Auth Role."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"auth/kubernetes/role/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading Kubernetes role '{name}': {e}")
            return None

    def delete_kubernetes_role(self, name):
        """Deletes a Kubernetes Auth Role."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"auth/kubernetes/role/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting Kubernetes role '{name}': {e}")
            return False

    def list_kubernetes_roles(self):
        """Lists all Kubernetes Auth Roles."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list("auth/kubernetes/role")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing Kubernetes roles: {e}")
            return []

    # -------------------------------------------------------------------------
    # KUBERNETES SECRETS ENGINE (JIT Dynamic Accounts)
    # -------------------------------------------------------------------------
    def setup_k8s_secrets_engine(self, mount_point, host, ca_cert, jwt):
        """Mounts and configures a K8s Secrets Engine."""
        client = self._get_client()
        if not client: return False
        try:
            current_mounts = client.sys.list_mounted_secrets_engines()['data']
            if f"{mount_point}/" not in current_mounts:
                client.sys.enable_secrets_engine('kubernetes', path=mount_point)
            
            # Configure engine with the cluster's API endpoint and credentials
            client.write(f"{mount_point}/config", kubernetes_host=host, kubernetes_ca_cert=ca_cert, service_account_jwt=jwt)
            return True
        except Exception as e:
            print(f"❌ Error setting up K8s Secrets engine: {e}")
            return False

    def teardown_k8s_secrets_engine(self, mount_point):
        """Unmounts a K8s Secrets Engine."""
        client = self._get_client()
        if not client: return False
        try:
            client.sys.disable_secrets_engine(mount_point)
            return True
        except Exception as e:
            print(f"❌ Error tearing down K8s Secrets engine: {e}")
            return False

    def read_k8s_engine_config(self, mount_point):
        """Reads the configuration of a K8s secrets engine."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"{mount_point}/config")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading config at '{mount_point}/': {e}")
            return None

    def update_k8s_engine_config(self, mount_point, host=None, ca_cert=None, jwt=None):
        """Updates specific fields in a K8s secrets engine config without wiping the others."""
        client = self._get_client()
        if not client: return False
        try:
            # Smart Merge: Read current state, then overwrite only what was provided
            current = self.read_k8s_engine_config(mount_point) or {}
            payload = {
                "kubernetes_host": host or current.get("kubernetes_host", ""),
                "kubernetes_ca_cert": ca_cert or current.get("kubernetes_ca_cert", ""),
                "service_account_jwt": jwt or current.get("service_account_jwt", "")
            }
            client.write(f"{mount_point}/config", **payload)
            return True
        except Exception as e:
            print(f"❌ Error updating config at '{mount_point}/': {e}")
            return False

    def create_k8s_secret_role(self, name, mount_point, rules_payload, allowed_namespaces=None, ttl="1h"):
        client = self._get_client()
        if not client: return False
        
        import yaml
        role_type = "Role"
        rules_string = rules_payload
        yaml_namespaces = None  # 🌟 NEW: Variable to hold YAML-defined namespaces
        
        try:
            import os
            if os.path.isfile(rules_payload):
                with open(rules_payload, 'r') as f:
                    data = yaml.safe_load(f)
            else:
                data = yaml.safe_load(rules_payload)

            if isinstance(data, dict):
                role_type = data.get("kind", "Role")
                yaml_namespaces = data.get("allowed_namespaces") # 🌟 NEW: Extract from YAML!
                
                # Vault ONLY wants the rules array, so we isolate it cleanly
                import json
                rules_string = json.dumps({"rules": data.get("rules", [])})
                
        except Exception as e:
            print(f"⚠️ Could not fully parse YAML: {e}")

        # 🧠 SMART UX: Prefer YAML namespaces, fallback to CLI argument, default to "default"
        if yaml_namespaces:
            if isinstance(yaml_namespaces, list):
                final_namespaces = [str(n).strip() for n in yaml_namespaces]
            else:
                final_namespaces = [n.strip() for n in str(yaml_namespaces).split(",")]
        elif allowed_namespaces:
            final_namespaces = [ns.strip() for ns in allowed_namespaces.split(",")]
        else:
            final_namespaces = ["default"]

        payload = {
            "kubernetes_role_type": role_type,
            "allowed_kubernetes_namespaces": final_namespaces, # 🌟 Dynamically set!
            "generated_role_rules": rules_string,
            "token_default_ttl": ttl,
            "token_max_ttl": ttl
        }
        
        try:
            client.write(f"{mount_point}/roles/{name}", **payload)
            return True
        except Exception as e:
            print(f"❌ Error creating K8s Secret Role '{name}': {e}")
            return False

    def read_k8s_secret_role(self, name, mount_point):
        """Reads a K8s secret role configuration."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"{mount_point}/roles/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading K8s role '{name}': {e}")
            return None

    def delete_k8s_secret_role(self, name, mount_point):
        """Deletes a K8s secret role."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"{mount_point}/roles/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting K8s role '{name}': {e}")
            return False

    def list_k8s_secret_roles(self, mount_point):
        """Lists active K8s secret roles."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list(f"{mount_point}/roles")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing K8s roles: {e}")
            return []

    def get_k8s_secret_token(self, role_name, k8s_namespace, mount_point, cluster_wide=False):
        """Requests a dynamic, ephemeral K8s Service Account token."""
        client = self._get_client()
        if not client: return None
        try:
            payload = {"kubernetes_namespace": k8s_namespace}
            
            # 🌟 NEW: Tell Vault to break out of the namespace sandbox
            if cluster_wide:
                payload["cluster_role_binding"] = True
                
            res = client.write(f"{mount_point}/creds/{role_name}", **payload)
            return res.get('data', {}).get('service_account_token')
        except Exception as e:
            print(f"❌ Error generating K8s token for '{role_name}': {e}")
            return None

    def get_k8s_engine_host(self, mount_point):
        """Retrieves the Kubernetes API host URL from the engine config."""
        client = self._get_client()
        if not client: return None
        try:
            # We read the /config endpoint of the secrets engine
            res = client.read(f"{mount_point}/config")
            return res.get('data', {}).get('kubernetes_host') if res else None
        except Exception as e:
            print(f"❌ Error fetching K8s host from Vault: {e}")
            return None


