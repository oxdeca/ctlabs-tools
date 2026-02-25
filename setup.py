from setuptools import setup, find_packages

setup(
    name="ctlabs-tools",
    version="0.1.40",
    description="ctlabs tools and helpers",
    packages=find_packages(),
    package_data={
      'ctlabs_tools.flashcards':['*html'],
    },
    include_package_data=True,
    zip_safe=False,
    install_requires=[
      "hvac",
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
        "gcp" : [
            "google-cloud-secret-manager>=2.16.0"
        ]
    },
    entry_points={
        'console_scripts': [
            'vault-login=ctlabs_tools.pytest.vault_login:main',
            'flashcards=ctlabs_tools.flashcards.server:main',
        ],
    },
)