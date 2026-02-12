from setuptools import setup, find_packages

setup(
    name="ctlabs-tools",
    version="0.1.2",
    description="ctlabs tools and helpers",
    packages=find_packages(),
    install_requires=[
      "hvac",
      "requests",
    ],
    entry_points={
        'console_scripts': [
            'vault-login=ctlabs_tools.pytest.vault_login:main', # Maps 'vault-login' command to main() function
        ],
    },
)