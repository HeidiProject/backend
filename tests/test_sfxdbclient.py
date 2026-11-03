import sys
from pathlib import Path
from unittest.mock import Mock

import pytest


APP_DIRECTORY = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIRECTORY))

from sfxdbclient import SFXDBClient


def test_client_uses_explicit_base_url(monkeypatch):
    monkeypatch.setenv("SFXDB_BASE_URL", "https://environment.example:8008")

    client = SFXDBClient(base_url="https://explicit.example:8008")

    assert client.base_url == "https://explicit.example:8008"
    client.close()


def test_client_uses_environment_base_url(monkeypatch):
    monkeypatch.setenv("SFXDB_BASE_URL", "https://environment.example:8008")

    client = SFXDBClient()

    assert client.base_url == "https://environment.example:8008"
    client.close()


@pytest.mark.parametrize("configured_url", [None, "", "   "])
def test_client_rejects_missing_or_empty_configuration(monkeypatch, configured_url):
    monkeypatch.delenv("SFXDB_BASE_URL", raising=False)
    if configured_url is None:
        with pytest.raises(ValueError, match="SFXDB base URL is not configured"):
            SFXDBClient()
    else:
        with pytest.raises(ValueError, match="SFXDB base URL is not configured"):
            SFXDBClient(base_url=configured_url)


def test_client_normalizes_whitespace_and_trailing_slash():
    client = SFXDBClient(base_url="  https://streaming.example:8008/  ")

    assert client.base_url == "https://streaming.example:8008"
    client.close()


def test_ffcs_campaign_request_uses_configured_base_url():
    client = SFXDBClient(base_url="https://streaming.example:8008/")
    response = Mock()
    response.json.return_value = [{"_id": {"campaignId": "campaign-a"}}]
    client.session.get = Mock(return_value=response)

    result = client.get_ffcs_campaigns(user_account="e12345")

    client.session.get.assert_called_once_with(
        "https://streaming.example:8008/ffcs-summary/",
        params={"user_account": "e12345"},
    )
    response.raise_for_status.assert_called_once_with()
    assert result == [{"_id": {"campaignId": "campaign-a"}}]
    client.close()
