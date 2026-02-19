from setuptools import setup, find_packages

setup(
    name="ctlabs-tools",
    version="0.1.11",
    description="ctlabs tools and helpers",
    packages=find_packages(),
    install_requires=[
      "hvac",
      "requests",
      "streamlit",
      "pandas",
      "cryptography",
    ],
    entry_points={
        'console_scripts': [
            'vault-login=ctlabs_tools.pytest.vault_login:main',
            'flashcards=ctlabs_tools.flashcards.server:main',
        ],
    },
)