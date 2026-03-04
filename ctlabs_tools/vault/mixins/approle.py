# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/mixins/approle.py
# License : MIT
# -----------------------------------------------------------------------------

class VaultAppRoleMixin:
    #
    # AppRoles
    #
    def approle_login(self, vault_url, role_id, secret_id):
        client = hvac.Client(url=vault_url, verify=False)
        try:
            res = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
            self._memory_token = res['auth']['client_token']
            self._memory_url = vault_url
            lease = res['auth'].get('lease_duration', 3600)
            self._memory_expiry = int(time.time()) + lease
            print("✅ AppRole login successful. Token stored in memory.")
            return True
        except Exception as e:
            print(f"❌ AppRole authentication failed: {e}")
            return False

    def create_or_update_approle(self, role_name, policies, ttl="1h"):
        client = self._get_client()
        if not client: return False
        try:
            client.auth.approle.create_or_update_approle(
                role_name=role_name,
                token_policies=policies,
                token_ttl=ttl,
                bind_secret_id=True
            )
            return True
        except Exception as e:
            print(f"❌ Error setting up AppRole {role_name}: {e}")
            return False

    def read_approle(self, role_name):
        """Fetches detailed properties of a specific AppRole."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.auth.approle.read_role(role_name=role_name)
            return res.get('data', {})
        except Exception as e:
            print(f"❌ Error reading AppRole {role_name}: {e}")
            return None

    def get_approle_credentials(self, role_name):
        client = self._get_client()
        if not client: return None
        try:
            role_id = client.auth.approle.read_role_id(role_name=role_name)['data']['role_id']
            secret_id = client.auth.approle.generate_secret_id(role_name=role_name)['data']['secret_id']
            return {"role_id": role_id, "secret_id": secret_id}
        except Exception as e:
            print(f"❌ Error fetching AppRole creds: {e}")
            return None

    def list_approles(self):
        """Fetches a list of all configured AppRoles."""
        client = self._get_client()
        if not client: return None
        try:
            # hvac returns a dict with 'keys' if successful
            res = client.auth.approle.list_roles()
            return res.get('data', {}).get('keys', [])
        except Exception as e:
            # A 404/InvalidPath usually just means no roles exist yet
            if "404" in str(e): return []
            print(f"❌ Error listing AppRoles: {e}")
            return None

    def delete_approle(self, role_name):
        """Deletes a specific AppRole."""
        client = self._get_client()
        if not client: return False
        try:
            client.auth.approle.delete_role(role_name=role_name)
            return True
        except Exception as e:
            print(f"❌ Error deleting AppRole {role_name}: {e}")
            return False

    def create_manager_policy(self, manager_name, target_role):
        """Creates a policy allowing a manager to issue SecretIDs for a target role."""
        client = self._get_client()
        if not client: return None

        policy_name = f"manager-{manager_name}-for-{target_role}"
        # Policy: Only allow generating SecretIDs for the specific target
        policy_hcl = f"""
        path "auth/approle/role/{target_role}/secret-id" {{
          capabilities = ["update"]
        }}
        """
        
        try:
            client.sys.create_or_update_policy(name=policy_name, policy=policy_hcl)
            return policy_name
        except Exception as e:
            print(f"❌ Failed to create manager policy: {e}")
            return None

    def setup_automated_approle(self, role_name, secret_path):
        """High-level helper to create policy and role in one shot."""
        # 1. Create the restricted policy
        policy_name = self.create_minimal_policy(role_name, secret_path)
        if not policy_name: return False

        # 2. Create the AppRole linked to that policy
        return self.create_or_update_approle(role_name, [policy_name])

