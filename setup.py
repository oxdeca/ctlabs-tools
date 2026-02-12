from setuptools import setup, find_packages

setup(
    name="ctlabs-tools",
    version="0.1.3",
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
            'ctlabs-nfs=ctlabs_tools.nfs.app:main',
            'ctlabs-postfix=ctlabs_tools.postfix.app:main',
            'ctlabs-kafka=ctlabs_tools.kafka.kafka:main',
            'ctlabs-smbadc=ctlabs_tools.smbadc.app:main',
            'ctlabs-slapd=ctlabs_tools.slapd.app:main',
        ],
    },
)