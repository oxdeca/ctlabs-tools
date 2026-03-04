# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/mixins/kv.py
# License : MIT
# -----------------------------------------------------------------------------

class VaultKVMixin:
    #
    # Secrets
    #
    def read_secret(self, path, mount_point='secret'):
        client = self._get_client()
        if not client: return None

        try:
            if mount_point.lower() == 'cubbyhole':
                response = client.read(f"cubbyhole/{path}")
                if response and 'data' in response:
                    return response['data']
                return None
            else:
                response = client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount_point)
                return response['data']['data']
        except Exception as e:
            print(f"❌ Error reading {mount_point}/{path}: {e}")
            return None

    def write_secret(self, path, secret_data, mount_point='secret'):
        client = self._get_client()
        if not client: return False

        try:
            if mount_point.lower() == 'cubbyhole':
                client.write(f"cubbyhole/{path}", **secret_data)
            else:
                client.secrets.kv.v2.create_or_update_secret(
                    path=path, 
                    secret=secret_data, 
                    mount_point=mount_point
                )
            print(f"✅ Successfully wrote secret to {mount_point}/{path}")
            return True
        except Exception as e:
            print(f"❌ Error writing secret to Vault: {e}")
            return False

    def list_secrets(self, path, mount_point='secret'):
        client = self._get_client()
        if not client: return None
        try:
            if mount_point in ['secret', 'kv', 'kvv2']:
                res = client.secrets.kv.v2.list_secrets(path=path, mount_point=mount_point)
            else:
                res = client.list(f"{mount_point}/{path}")

            return res.get('data', {}).get('keys', [])
        except Exception as e:
            # Vault throws an InvalidPath/404 when trying to list a leaf node.
            # We fail silently here so the CLI can smoothly fall back to a "read".
            error_str = str(e)
            if "404" in error_str or "InvalidPath" in type(e).__name__ or "None, on list" in error_str:
                return []
            
            print(f"❌ Error listing secrets at {mount_point}/{path}: {e}")
            return None

    def search_secrets(self, base_path, search_pattern, mount_point='secret'):
        """Safely yields paths and matched keys, evaluating both folder/secret names and payload keys."""
        client = self._get_client()
        if not client: return
        
        import re
        try:
            regex = re.compile(search_pattern, re.IGNORECASE)
        except re.error as e:
            print(f"❌ Invalid regex pattern '{search_pattern}': {e}")
            return

        def _recurse(current, is_folder=True):
            path_matches = bool(regex.search(current))
            
            if is_folder:
                # If the folder path itself matches, yield it immediately
                if path_matches and current != base_path:
                    yield current, [], True, True # path, matched_keys, path_matches, is_folder
                
                try:
                    res = client.secrets.kv.v2.list_secrets(path=current, mount_point=mount_point)
                    keys = res.get('data', {}).get('keys', [])
                    for k in keys:
                        next_path = f"{current}/{k}" if current else k
                        if k.endswith('/'):
                            yield from _recurse(next_path.rstrip('/'), is_folder=True)
                        else:
                            yield from _recurse(next_path, is_folder=False)
                except Exception as e:
                    # If listing fails on the base_path, it might actually be a leaf node
                    if current == base_path:
                        yield from _recurse(current, is_folder=False)
            else:
                # It's a secret (leaf node). Read the payload to check the keys.
                matched_keys = []
                try:
                    secret_res = client.secrets.kv.v2.read_secret_version(path=current, mount_point=mount_point)
                    secret_data = secret_res.get('data', {}).get('data', {})
                    matched_keys = [sk for sk in secret_data.keys() if regex.search(sk)]
                except Exception:
                    pass # Ignore permission errors
                
                # Yield if the secret's path matches OR if any keys inside matched
                if path_matches or matched_keys:
                    yield current, matched_keys, path_matches, False

        yield from _recurse(base_path, is_folder=True)

    def resolve_mapped_config(self, config):
        results = {}
        mount_point = config.get("mount", "kvv2")
        
        for secret_def in config.get("secrets", []):
            name = secret_def["name"]
            path = secret_def["path"]
            
            data = self.read_secret(path=path, mount_point=mount_point)
            if data:
                results[name] = data.get(name, data)
            else:
                results[name] = None
                
        return results

