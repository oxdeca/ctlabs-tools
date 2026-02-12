from setuptools import setup, find_packages

setup(
    name="ctlabs-tools",
    version="0.1.1",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'vault-login=pytest.vault_login:main', # Maps 'vault-login' command to main() function
        ],
    },
)