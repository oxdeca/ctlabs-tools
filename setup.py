from setuptools import setup, find_packages

setup(
    name="ctlabs-tools",
    version="0.1.63",
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
            'vault-login=ctlabs_tools.pytest.vault_login:main',
            'vault-approle=ctlabs_tools.pytest.vault_approle:main',
            'vault-secret=ctlabs_tools.pytest.vault_secret:main',
            'flashcards=ctlabs_tools.flashcards.server:main',
        ],
    },
)