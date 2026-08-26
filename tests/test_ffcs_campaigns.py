import importlib
import sys
import types
from pathlib import Path

import pytest
import yaml


@pytest.fixture()
def server_module(monkeypatch):
    """Import the Flask app with all database dependencies replaced by fakes."""
    app_directory = Path(__file__).resolve().parents[1] / "app"
    monkeypatch.chdir(app_directory)
    monkeypatch.syspath_prepend(str(app_directory))

    fake_database = types.ModuleType("mongo_database")
    fake_database.adp_get_results = lambda *args, **kwargs: []
    fake_database.create_token = lambda *args, **kwargs: {}
    fake_database.delete_token = lambda *args, **kwargs: {}
    fake_database.get_token = lambda *args, **kwargs: None
    fake_database.get_tokens = lambda *args, **kwargs: []
    fake_database.get_user = lambda *args, **kwargs: {}
    fake_database.vespa_get_results = lambda *args, **kwargs: []
    fake_database.summary_get_results = lambda *args, **kwargs: []
    fake_database.ffcs_get_results = lambda *args, **kwargs: []
    fake_database.ffcs_get_campaign_results = lambda *args, **kwargs: []
    monkeypatch.setitem(sys.modules, "mongo_database", fake_database)

    fake_importer = types.ModuleType("sample_importer")
    fake_importer.SampleSpreadsheetImporter = object
    fake_importer.SpreadsheetImportError = ValueError
    monkeypatch.setitem(sys.modules, "sample_importer", fake_importer)
    monkeypatch.setattr(
        yaml,
        "safe_load",
        lambda stream: {"mongo": {"API_KEY": "test-api-key"}},
    )

    sys.modules.pop("server", None)
    module = importlib.import_module("server")
    yield module
    sys.modules.pop("server", None)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("12345", ("p12345", "e12345")),
        ("p12345", ("p12345", "e12345")),
        ("e12345", ("p12345", "e12345")),
        (" P12345 ", ("p12345", "e12345")),
    ],
)
def test_normalize_experiment_account(server_module, value, expected):
    assert server_module.normalize_experiment_account(value) == expected


@pytest.mark.parametrize("value", [None, "", "x12345", "p12-345"])
def test_normalize_experiment_account_rejects_invalid_values(server_module, value):
    with pytest.raises(ValueError):
        server_module.normalize_experiment_account(value)


def test_campaign_list_is_authorized_normalized_and_sorted(server_module, monkeypatch):
    observed_accounts = []

    def fake_campaigns(user_account):
        observed_accounts.append(user_account)
        return [
            {"_id": {"campaignId": "campaign-b"}},
            {"_id": {"campaignId": "campaign-a"}},
            {"_id": {"campaignId": "campaign-a"}},
        ]

    monkeypatch.setattr(server_module, "ffcs_get_results", fake_campaigns)
    client = server_module.create_app().test_client()

    response = client.post(
        "/api/ffcs",
        json={"user_account": "p12345"},
        headers={"X-PGROUPS": "p99999 p12345"},
    )

    assert response.status_code == 200
    assert response.get_json() == [
        {"campaign_id": "campaign-a", "display_name": "campaign-a"},
        {"campaign_id": "campaign-b", "display_name": "campaign-b"},
    ]
    assert observed_accounts == ["e12345"]


def test_campaign_list_rejects_another_users_account(server_module, monkeypatch):
    database_called = False

    def fake_campaigns(user_account):
        nonlocal database_called
        database_called = True
        return []

    monkeypatch.setattr(server_module, "ffcs_get_results", fake_campaigns)
    client = server_module.create_app().test_client()

    response = client.post(
        "/api/ffcs",
        json={"user_account": "p12345"},
        headers={"X-PGROUPS": "p99999"},
    )

    assert response.status_code == 403
    assert database_called is False


def test_campaign_list_accepts_authorized_api_token(server_module, monkeypatch):
    token = "12345678-1234-4234-9234-123456789abc"
    monkeypatch.setattr(server_module, "get_token", lambda token_id: "p12345")
    monkeypatch.setattr(
        server_module,
        "ffcs_get_results",
        lambda user_account: [{"_id": {"campaignId": "campaign-a"}}],
    )
    client = server_module.create_app().test_client()

    response = client.post(
        "/api/ffcs",
        json={"user_account": "p12345"},
        headers={"Authorization": f"X-API-TOKEN {token}"},
    )

    assert response.status_code == 200
    assert response.get_json()[0]["campaign_id"] == "campaign-a"


def test_campaign_wells_use_authorized_eaccount(server_module, monkeypatch):
    observed_query = {}

    def fake_wells(user_account, campaign_id):
        observed_query.update(
            user_account=user_account,
            campaign_id=campaign_id,
        )
        return [{"document": [{"well": "A01"}]}]

    monkeypatch.setattr(server_module, "ffcs_get_campaign_results", fake_wells)
    client = server_module.create_app().test_client()

    response = client.post(
        "/api/campaign",
        json={"user_account": "p12345", "campaign_id": " campaign-a "},
        headers={"X-PGROUPS": "p12345"},
    )

    assert response.status_code == 200
    assert observed_query == {
        "user_account": "e12345",
        "campaign_id": "campaign-a",
    }


def test_campaign_wells_require_campaign_id(server_module):
    client = server_module.create_app().test_client()

    response = client.post(
        "/api/campaign",
        json={"user_account": "p12345", "campaign_id": ""},
        headers={"X-PGROUPS": "p12345"},
    )

    assert response.status_code == 400
