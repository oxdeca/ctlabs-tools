# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/mixins/ssh.py
# -----------------------------------------------------------------------------

class VaultSSHMixin:
    def setup_ssh_engine(self, mount_point, key_type="ed25519"):
        client = self._get_client()
        if not client: return False
        try:
            current_mounts = client.sys.list_mounted_secrets_engines()['data']
            if f"{mount_point}/" not in current_mounts:
                client.sys.enable_secrets_engine('ssh', path=mount_point)
            
            # 🌟 FIX: Force Vault to generate a modern ed25519 CA key instead of RSA!
            client.write(
                f"{mount_point}/config/ca", 
                generate_signing_key=True,
                key_type=key_type 
            )
            return True
        except Exception as e:
            print(f"❌ Error setting up SSH engine: {e}")
            return False

    def teardown_ssh_engine(self, mount_point):
        client = self._get_client()
        if not client: return False
        try:
            client.sys.disable_secrets_engine(mount_point)
            return True
        except Exception as e:
            print(f"❌ Error tearing down SSH engine: {e}")
            return False

    def create_ssh_role(self, name, mount_point, default_user, allowed_users, ttl="4h"):
        client = self._get_client()
        if not client: return False
        try:
            users = allowed_users if isinstance(allowed_users, str) else ",".join(allowed_users)
            client.write(
                f"{mount_point}/roles/{name}",
                key_type="ca",
                default_user=default_user,
                allowed_users=users,
                allow_user_certificates=True,
                default_extensions={"permit-pty": ""},
                max_ttl=ttl
            )
            return True
        except Exception as e:
            print(f"❌ Error creating SSH role: {e}")
            return False

    def sign_ssh_key(self, role_name, mount_point, public_key_string, valid_principals):
        client = self._get_client()
        if not client: return None
        try:
            res = client.write(
                f"{mount_point}/sign/{role_name}",
                public_key=public_key_string,
                valid_principals=valid_principals
            )
            return res.get('data', {}).get('signed_key')
        except Exception as e:
            print(f"❌ Error signing SSH key: {e}")
            return None
