import pytest

from src.aws_manager import AuthorizationError
from src.config import EXECUTE_AUTHORIZATION_PHRASE
from src.ssm_executor import require_execute_authorization


def test_execute_requires_exact_phrase():
    with pytest.raises(AuthorizationError):
        require_execute_authorization(None)
    with pytest.raises(AuthorizationError):
        require_execute_authorization("autorizo")
    require_execute_authorization(EXECUTE_AUTHORIZATION_PHRASE)
