from setuptools import setup, find_packages

setup(
    name="ctlabs-tools",
    version="0.3.36",
    description="CTLabs tools and helpers",
    packages=find_packages(),
    package_data={
      'ctlabs_tools.flashcards': ['*.html'],
    },
    include_package_data=True,
    zip_safe=False,
    install_requires=[
      "hvac",
      "jmespath",
      "pytest",
      "requests",
      "streamlit",
      "pandas",
      "cryptography",
      "flask",
      "flask-jwt-extended",
      "pyyaml",
      "python-dotenv",
    ],
    extras_require={
        "gcp": [
            "google-cloud-secret-manager>=2.16.0"
        ],
        "all": [
            "google-cloud-secret-manager>=2.16.0"
        ]
    },
    entry_points={
        'console_scripts': [
            'vault-login=ctlabs_tools.vault.vault_login:main',
            'vault-auth=ctlabs_tools.vault.vault_auth:main',
            'vault-secret=ctlabs_tools.vault.vault_secret:main',
            'vault-ldap=ctlabs_tools.vault.vault_ldap:main',
            'vault-gcp=ctlabs_tools.vault.vault_gcp:main',
            'vault-k8s=ctlabs_tools.vault.vault_k8s:main',
            'vault-ssh=ctlabs_tools.vault.vault_ssh:main',
            'vault-pki=ctlabs_tools.vault.vault_pki:main',
            'vault-trap=ctlabs_tools.vault.vault_trap:main',
            'vault-audit=ctlabs_tools.vault.vault_audit:main',
            'flashcards=ctlabs_tools.flashcards.server:main',
        ],
    },
)