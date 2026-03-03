from setuptools import setup, find_packages

setup(
    name="ctlabs-tools",
    version="0.2.53",
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
            'vault-gcp=ctlabs_tools.vault.vault_gcp:main',
            'vault-k8s=ctlabs_tools.vault.vault_k8s:main',
            'flashcards=ctlabs_tools.flashcards.server:main',
        ],
    },
)