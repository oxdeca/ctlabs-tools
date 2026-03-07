# -----------------------------------------------------------------------------
# File    : ctlabs-tools/ctlabs_tools/vault/base.py
# License : MIT
# -----------------------------------------------------------------------------

class VaultIdentityMixin:
    # -------------------------------------------------------------------------
    # USERPASS / LDAP MANAGEMENT
    # -------------------------------------------------------------------------
    def create_user(self, username, password=None, policies=None, auth_type="userpass"):
        """Creates or updates a human user in Vault."""
        client = self._get_client()
        if not client: return False
        
        payload = {}
        if policies:
            payload['policies'] = policies if isinstance(policies, list) else [p.strip() for p in policies.split(",")]
        if password and auth_type == "userpass":
            payload['password'] = password
            
        try:
            client.write(f"auth/{auth_type}/users/{username}", **payload)
            return True
        except Exception as e:
            print(f"❌ Error creating {auth_type} user '{username}': {e}")
            return False

    def read_user(self, username, auth_type="userpass"):
        """Reads configuration details for a human user."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"auth/{auth_type}/users/{username}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading {auth_type} user '{username}': {e}")
            return None

    def delete_user(self, username, auth_type="userpass"):
        """Deletes a human user."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"auth/{auth_type}/users/{username}")
            return True
        except Exception as e:
            print(f"❌ Error deleting {auth_type} user '{username}': {e}")
            return False

    def list_users(self, auth_type="userpass"):
        """Lists all users for a specific auth method."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list(f"auth/{auth_type}/users")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing {auth_type} users: {e}")
            return []

    # -------------------------------------------------------------------------
    # AUTH GROUP MANAGEMENT (LDAP/OIDC)
    # -------------------------------------------------------------------------
    def create_group(self, name, policies=None, auth_type="ldap"):
        """Maps an external auth group (like LDAP) to Vault policies."""
        client = self._get_client()
        if not client: return False
        
        payload = {}
        if policies:
            payload['policies'] = policies if isinstance(policies, list) else [p.strip() for p in policies.split(",")]
            
        try:
            client.write(f"auth/{auth_type}/groups/{name}", **payload)
            return True
        except Exception as e:
            print(f"❌ Error creating {auth_type} group '{name}': {e}")
            return False

    def read_group(self, name, auth_type="ldap"):
        """Reads configuration details for an auth group."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"auth/{auth_type}/groups/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading {auth_type} group '{name}': {e}")
            return None

    def delete_group(self, name, auth_type="ldap"):
        """Deletes an auth group mapping."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"auth/{auth_type}/groups/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting {auth_type} group '{name}': {e}")
            return False

    def list_groups(self, auth_type="ldap"):
        """Lists all mapped groups for a specific auth method."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list(f"auth/{auth_type}/groups")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing {auth_type} groups: {e}")
            return []

    # -------------------------------------------------------------------------
    # IDENTITY GROUP MANAGEMENT (Internal Vault Groups)
    # -------------------------------------------------------------------------
    def create_identity_group(self, name, policies=None, member_entity_ids=None):
        client = self._get_client()
        if not client: return False
        
        payload = {}
        if policies:
            payload['policies'] = policies if isinstance(policies, list) else [p.strip() for p in policies.split(",")]
        if member_entity_ids:
            payload['member_entity_ids'] = member_entity_ids
            
        try:
            client.write(f"identity/group/name/{name}", **payload)
            return True
        except Exception as e:
            print(f"❌ Error creating identity group '{name}': {e}")
            return False

    def read_identity_group(self, name):
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"identity/group/name/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading identity group '{name}': {e}")
            return None

    def delete_identity_group(self, name):
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"identity/group/name/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting identity group '{name}': {e}")
            return False

    def list_identity_groups(self):
        client = self._get_client()
        if not client: return []
        try:
            res = client.list("identity/group/name")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing identity groups: {e}")
            return []


    # -------------------------------------------------------------------------
    # IDENTITY ENTITY MANAGEMENT
    # -------------------------------------------------------------------------
    def create_entity(self, name, policies=None):
        """Creates or updates a Vault Identity Entity."""
        client = self._get_client()
        if not client: return False
        
        payload = {}
        if policies:
            payload['policies'] = policies if isinstance(policies, list) else [p.strip() for p in policies.split(",")]
            
        try:
            # Vault standardizes entity creation by name here
            client.write(f"identity/entity/name/{name}", **payload)
            return True
        except Exception as e:
            print(f"❌ Error creating entity '{name}': {e}")
            return False

    def read_entity(self, name):
        """Reads configuration details for an entity."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"identity/entity/name/{name}")
            return res.get('data') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading entity '{name}': {e}")
            return None

    def delete_entity(self, name):
        """Deletes an identity entity."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"identity/entity/name/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting entity '{name}': {e}")
            return False

    def list_entities(self):
        """Lists all identity entities."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list("identity/entity/name")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error listing entities: {e}")
            return []

    def merge_entities(self, from_entity_name, to_entity_name):
        """Merges one entity (and its aliases) into another, deleting the source."""
        client = self._get_client()
        if not client: return False
        
        # 1. Look up the UUIDs for both entities
        from_ent = self.read_entity(from_entity_name)
        to_ent = self.read_entity(to_entity_name)
        
        if not from_ent or 'id' not in from_ent:
            print(f"❌ Error: Source entity '{from_entity_name}' not found.")
            return False
        if not to_ent or 'id' not in to_ent:
            print(f"❌ Error: Target entity '{to_entity_name}' not found.")
            return False
            
        # 2. Fire the merge API call
        try:
            client.write(
                "identity/entity/merge",
                from_entity_ids=[from_ent['id']],
                to_entity_id=to_ent['id']
            )
            return True
        except Exception as e:
            print(f"❌ Error merging entities: {e}")
            return False

    # -------------------------------------------------------------------------
    # IDENTITY ALIAS MANAGEMENT
    # -------------------------------------------------------------------------
    def get_auth_accessor(self, mount_point):
        """Resolves a human-readable auth mount point to its internal Accessor UUID."""
        client = self._get_client()
        if not client: return None
        
        # Vault stores mounts with a trailing slash in sys/auth (e.g., 'ldap/')
        mount_point = mount_point.strip('/') + '/'
        try:
            auth_methods = client.sys.list_auth_methods().get('data', {})
            if mount_point in auth_methods:
                return auth_methods[mount_point].get('accessor')
            return None
        except Exception as e:
            print(f"❌ Error fetching auth accessor for '{mount_point}': {e}")
            return None

    def create_entity_alias(self, entity_name, alias_name, mount_point="userpass"):
        """Smart Alias: Links a login name to an Entity by resolving UUIDs automatically."""
        client = self._get_client()
        if not client: return False

        # 1. Resolve Entity UUID
        entity = self.read_entity(entity_name)
        if not entity or 'id' not in entity:
            print(f"❌ Error: Entity '{entity_name}' not found. Create it first.")
            return False
        
        # 2. Resolve Auth Mount UUID
        accessor = self.get_auth_accessor(mount_point)
        if not accessor:
            print(f"❌ Error: Auth mount '{mount_point}' not found or inaccessible.")
            return False

        # 3. Map them together!
        try:
            client.write(
                "identity/entity-alias",
                name=alias_name,
                canonical_id=entity['id'],
                mount_accessor=accessor
            )
            return True
        except Exception as e:
            print(f"❌ Error creating alias '{alias_name}' for entity '{entity_name}': {e}")
            return False

    def delete_entity_alias(self, entity_name, alias_name, mount_point="userpass"):
        """Smart Alias: Finds and deletes a specific alias from an entity."""
        client = self._get_client()
        if not client: return False
        
        accessor = self.get_auth_accessor(mount_point)
        entity = self.read_entity(entity_name)
        if not entity or 'aliases' not in entity: return False
        
        # Find the specific alias UUID inside the entity's data
        alias_id = None
        for alias in entity['aliases']:
            if alias['name'] == alias_name and alias['mount_accessor'] == accessor:
                alias_id = alias['id']
                break
                
        if not alias_id:
            print(f"⚠️ Alias '{alias_name}' on '{mount_point}' not found for entity '{entity_name}'.")
            return False
            
        try:
            client.delete(f"identity/entity-alias/id/{alias_id}")
            return True
        except Exception as e:
            print(f"❌ Error deleting alias: {e}")
            return False


    # -------------------------------------------------------------------------
    # POLICY MANAGEMENT
    # -------------------------------------------------------------------------
    def create_policy(self, name, rules):
        """Creates or updates an ACL policy using the modern endpoint."""
        client = self._get_client()
        if not client: return False
        try:
            # Directly hit the modern ACL path
            client.write(f"sys/policies/acl/{name}", policy=rules)
            return True
        except Exception as e:
            print(f"❌ Error creating policy '{name}': {e}")
            return False

    def read_policy(self, name):
        """Reads an existing ACL policy using the modern endpoint."""
        client = self._get_client()
        if not client: return None
        try:
            res = client.read(f"sys/policies/acl/{name}")
            return res.get('data', {}).get('policy') if res else None
        except Exception as e:
            if "404" not in str(e): print(f"❌ Error reading policy '{name}': {e}")
            return None

    def delete_policy(self, name):
        """Deletes an ACL policy using the modern endpoint."""
        client = self._get_client()
        if not client: return False
        try:
            client.delete(f"sys/policies/acl/{name}")
            return True
        except Exception as e:
            print(f"❌ Error deleting policy '{name}': {e}")
            return False


    def list_policies(self):
        """Lists all ACL policies using the modern endpoint."""
        client = self._get_client()
        if not client: return []
        try:
            res = client.list("sys/policies/acl")
            return res.get('data', {}).get('keys', []) if res else []
        except Exception as e:
            print(f"❌ Error listing policies: {e}")
            return []

    def create_minimal_policy(self, role_name, secret_path, gcp_roleset=None):
        """Creates a standard restricted policy for a specific AppRole (KVv2 Aware)."""
        client = self._get_client()
        if not client: return None

        policy_name = f"policy-{role_name}"
        
        # BUGFIX: Handle KVv2 data/ and metadata/ routing
        # If the user passes 'kv/my-app', we split it to 'kv/data/my-app'
        parts = secret_path.split('/', 1)
        if len(parts) > 1:
            mount = parts[0]
            path = parts[1]
            data_path = f"{mount}/data/{path}"
            meta_path = f"{mount}/metadata/{path}"
        else:
            data_path = secret_path
            meta_path = secret_path

        policy_hcl = f"""
        # Allow reading the actual secret data
        path "{data_path}/*" {{ capabilities = ["read", "list"] }}
        path "{data_path}"   {{ capabilities = ["read", "list"] }}
        
        # Allow reading the secret metadata (required by many tools)
        path "{meta_path}/*" {{ capabilities = ["read", "list"] }}
        path "{meta_path}"   {{ capabilities = ["read", "list"] }}
        """

        if gcp_roleset:
            # 🧠 SMART FIX: Automatically inject the /token/ pathing for the user
            # e.g., "gcp/my-project/devops" -> "gcp/my-project/token/devops"
            parts = gcp_roleset.rsplit('/', 1)
            if len(parts) == 2:
                gcp_path = f"{parts[0]}/token/{parts[1]}"
            else:
                gcp_path = f"gcp/token/{gcp_roleset}" # Fallback for old default mounts

            policy_hcl += f"""
            # Allow generating dynamic GCP OAuth tokens for {gcp_roleset}
            path "{gcp_path}" {{
              capabilities = ["read"]
            }}
            """
        
        try:
            client.sys.create_or_update_policy(name=policy_name, policy=policy_hcl)
            print(f"✅ Created minimal KVv2 policy: {policy_name}")
            return policy_name
        except Exception as e:
            print(f"❌ Failed to create policy: {e}")
            return None



