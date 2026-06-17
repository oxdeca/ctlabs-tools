import pytest
from ctlabs_tools.pytest.helper import Terraform, Ansible, ConfTest
from ctlabs_tools.vault.core    import HashiVault

def pytest_addoption(parser):
    """Register the --interactive flag for the entire test suite."""
    parser.addoption(
        "--interactive",
        action="store_true",
        default=False,
        help="Enable interactive retry loops on failures"
    )

@pytest.fixture(scope="session")
def is_interactive(request):
    """Returns True if --interactive was passed in the command line."""
    return request.config.getoption("--interactive")

@pytest.fixture(scope="session")
def vault_auth():
    """Provides a single Vault instance for the test session."""
    return HashiVault()

@pytest.fixture(scope="session")
def tf(is_interactive, vault_auth):
    """Shared Terraform fixture with Vault auth injected."""
    t = Terraform(
        wd=".",
        interactive=is_interactive,
        auth_callback=vault_auth.ensure_valid_token # Injects the auth check!
    )
    yield t
    t.cleanup()

@pytest.fixture(scope="session")
def tf_stack(tf, is_interactive, vault_auth):
    tf.init()
    tf.plan()
    has_changes = tf.has_changes()

    if has_changes:
        print("\n[CONFTEST] Evaluating Terraform plan against Rego policies...")
        policy_checker = ConfTest(wd=".", input="tfplan.json", interactive=is_interactive, auth_callback=vault_auth.ensure_valid_token)
        policy_checker.run(ns="main")

    tf.show_changes()
    tf.apply()
    tf.has_changes = has_changes
    yield tf
    tf.cleanup()
    print("")
    tf.destroy()
