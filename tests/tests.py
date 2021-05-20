import datetime
import pytest

from common.auth import get_service_tapis_client, tenants
import tapipy

@pytest.fixture
def client():
    return get_service_tapis_client(tenants=tenants)


def test_get_service_tapis_client(client):
    assert client is not None


def test_get_tenants(client):
    mast_ten = client.tenant_cache.get_tenant_config(tenant_id='admin')
    assert 'tapis.io' in mast_ten.base_url
    tacc_site = mast_ten.site
    assert '${tenant_id}' in tacc_site.tenant_base_url_template
    assert 'tapis.io' in tacc_site.tenant_base_url_template


def test_get_tenant_by_url(client):
    mast_ten = client.tenant_cache.get_tenant_config(url='https://admin.develop.tapis.io')
    assert 'tapis.io' in mast_ten.base_url
    tacc_site = mast_ten.site
    assert tacc_site.site_id
    assert '${tenant_id}' in tacc_site.tenant_base_url_template
    assert 'tapis.io' in tacc_site.tenant_base_url_template


def test_reload_tenants(client):
    client.tenant_cache.reload_tenants()
    admin_ten = client.tenant_cache.get_tenant_config(tenant_id='admin')
    assert 'tapis.io' in admin_ten.base_url
    tacc_site = admin_ten.site
    assert '${tenant_id}' in tacc_site.tenant_base_url_template
    assert 'tapis.io' in tacc_site.tenant_base_url_template


def token_checks(client):
    assert client.service_tokens
    assert client.service_tokens['admin']
    assert client.service_tokens['admin']['access_token']
    assert type(client.service_tokens['admin']['access_token']) == tapipy.tapis.TapisResult
    access_token = client.service_tokens['admin']['access_token']
    assert access_token.access_token
    assert access_token.claims
    assert access_token.expires_at
    assert type(access_token.expires_at) ==  datetime.datetime
    assert access_token.expires_in()
    assert type(access_token.expires_in()) == datetime.timedelta
    assert client.service_tokens['admin']['refresh_token']


def test_service_tokens(client):
    # first check that the service tokens are there
    token_checks(client)


def test_service_tokens_refresh(client):
    # refresh two times, checking the tokens each time
    client.refresh_tokens(tenant_id='admin')
    token_checks(client)
    # second time --
    client.refresh_tokens(tenant_id='admin')
    token_checks(client)


#def test_get_base_url_for_service_request(client):
#    assert client.tenant_cache.get_base_url_for_service_request(tenant_id='dev', service='tokens') \
#           == 'https://dev.develop.tapis.io'
#
#    assert client.tenant_cache.get_base_url_for_service_request(tenant_id='admin', service='tokens') \
#           == 'https://admin.develop.tapis.io'


def test_determine_x_tenant_for_request(client):
    assert client.tokens.create_token.determine_tenant_id_for_service_request() == 'admin'


def test_determine_x_tenant_for_request_param(client):
    assert client.tokens.create_token.determine_tenant_id_for_service_request(_tapis_tenant_id='fooy') == 'fooy'


def test_determine_x_user_for_request(client):
    assert client.tokens.create_token.determine_user_for_service_request() == 'authenticator'


def test_determine_x_user_for_request_param(client):
    assert client.tokens.create_token.determine_user_for_service_request(_tapis_user='fooy') == 'fooy'


def test_get_base_url_for_tenant_primary_site(client):
    assert client.tenant_cache.get_base_url_for_tenant_primary_site(tenant_id='dev') == 'https://dev.develop.tapis.io'




