import base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

from flask import g, request
import jwt
from tapy.dyna import DynaTapy

from common.config import conf
from common import errors
from common.logs import get_logger
logger = get_logger(__name__)

def get_service_tapy_client(tenant_id=None, base_url=None):
    """
    Returns a Tapy client for the service using the service's configuration. If tenant_id is not passed, uses the first
    tenant in the service's tenants configuration.
    :param tenant_id: (str) The tenant_id associated with the tenant to configure the client with.
    :param base_url: (str) The base URL for the tenant to configure the client with.
    :return: (tapy.dyna.dynatapy.DynaTapy) A Tapy client object.
    """
    # if there is no tenant_id, use the instance base url configured for the service:
    if not tenant_id:
        tenant_id = conf.tenants[0]
    if not base_url:
        base_url = conf.instance_base_url
    t = DynaTapy(base_url=base_url,
                 tenant_id=tenant_id,
                 username=conf.service_name,
                 account_type='service')
    t.get_tokens()
    return t

def get_tenants():
    """
    Retrieve the set of tenants and associated data that this service instance is serving requests for.
    :return:
    """
    # these are the tenant_id strings configured for the service -
    tenants_strings = conf.tenants
    result = []
    # the tenants service is a special case, as it must be a) configured to serve all tenants and b) actually maintains
    # the list of tenants in its own DB. in this case, we return the empty list since the tenants service will use direct
    # db access to get necessary data.
    if conf.service_name == 'tenants' and tenants_strings[0] == '*':
        return result

    # in dev mode, services can be configured to not use the security kernel, in which case we must get
    # configuration for a "dev" tenant directly from the service configs:
    if not conf.use_sk:
        for tenant in tenants_strings:
            t = {'tenant_id': tenant,
                 'iss': conf.dev_iss,
                 'public_key': conf.dev_jwt_public_key,
                 }
            result.append(t)

    else:
        t = DynaTapy(base_url=conf.instance_base_url)
        tenant_list = t.tenants.list_tenants()
        for tn in tenant_list:
            t = {'tenant_id': tn.tenant_id,
                 'iss': tn.token_service,
                 'public_key': tn.public_key
            }
            result.append(t)
    return result

# singleton object with all the tenant configurations, as a python dictionary:
# NOTE: since this object is constructed once at service initialization, it can grown stale as new tenants are
#       added. ideally, adding/modifying tenants would not require service restarts, but instead would send the services
#       a message to reload their tenant objects.
tenants = get_tenants()

def get_tenant_config(tenant_id):
    """
    Return the config for a specific tenant_id from the tenants config.
    :param tenant_id:
    :return:
    """
    for tenant in tenants:
        if tenant['tenant_id'] == tenant_id:
            return tenant
    raise errors.BaseTapisError("invalid tenant id.")

def authn_and_authz(authn_callback=None, authz_callback=None):
    """All-in-one convenience function for implementing the basic Tapis authentication
    and authorization on a flask app.

    Pass authn_callback, a Python callable, to handle custom authentication mechanisms (such as nonce) when a JWT
    is not present. (Only called when JWT is not present; not called when JWT is invalid.

    Pass authz_callback, a Python callable, to do additional custom authorization
    checks within your app after the initial checks.

    Basic usage is as follows:

    import auth

    my_app = Flask(__name__)
    @my_app.before_request
    def authnz_for_my_app():
        auth.authn_and_authz()

    """
    authentication(authn_callback)
    authorization(authz_callback)


def authentication(authn_callback=None):
    """Entry point for authentication. Use as follows:

    import auth

    my_app = Flask(__name__)
    @my_app.before_request
    def authn_for_my_app():
        auth.authentication()

    """
    add_headers()
    validate_request_token()

def authorization(authz_callback=None):
    """Entry point for authorization. Use as follows:

    import auth

    my_app = Flask(__name__)
    @my_app.before_request
    def authz_for_my_app():
        auth.authorization()

    """
    if request.method == 'OPTIONS':
        # allow all users to make OPTIONS requests
        return

    if authz_callback:
        authz_callback()

def add_headers():
    """
    Adds the standard Tapis headers to the flask thread local.

    :return:
    """
    # the actual access token -
    g.x_tapis_token = request.headers.get('X-Tapis-Token')

    # the tenant associated with the subject of the request; used, for instance, when the subject is different
    # from the subject in the actual access_token (for example, when the access_token represents a service account).
    g.x_tapis_tenant = request.headers.get('X-Tapis-Tenant')

    # the user associated with the subject of the request. Similar to x_tapis_tenant, this is used, for instance, when
    # the subject is different from the subject in the actual access_token (for example, when the access_token
    # represents a service account).
    g.x_tapis_user = request.headers.get('X-Tapis-User')

    # a hash of the original user's access token. this can be used, for instance, to check if the original user's
    # access token has been revoked.
    g.x_tapis_user_token_hash = request.headers.get('X-Tapis-User-Token-Hash')


def validate_request_token():
    """
    Attempts to validate the Tapis access token in the request based on the public key and signature in the JWT.
    This function raises
        - NoTokenError - if no token is present in the request.
        - AuthenticationError - if validation is not successful.
    :return:
    """
    if not hasattr(g, 'x_tapis_token'):
        raise errors.NoTokenError("No access token found in the request.")
    claims = validate_token(g.x_tapis_token)
    g.token_claims = claims
    g.username = claims.get('tapis/username')
    g.tenant_id = claims.get('tapis/tenant_id')
    g.account_type = claims.get('tapis/account_type')
    g.delegation = claims.get('tapis/delegation')


def validate_token(token):
    """
    Stand-alone function to validate a Tapis token. 
    :param token: 
    :return: 
    """
    # first, decode the token data to determine the tenant associated with the token. We are not able to
    # check the signature until we know which tenant, and thus, which public key, to use for validation.
    if not token:
        raise errors.NoTokenError("No Tapis access token found in the request.")
    try:
        data = jwt.decode(token, verify=False)
    except Exception as e:
        logger.debug(f"got exception trying to parse data from the access_token jwt; exception: {e}")
        raise errors.AuthenticationError("Could not parse the Tapis access token.")
    logger.debug(f"got data from token: {data}")
    # get the tenant out of the jwt payload and get associated public key
    try:
        token_tenant_id = data['tapis/tenant_id']
    except KeyError:
        raise errors.AuthenticationError("Unable to process Tapis token; could not parse the tenant_id. It is possible "
                                         "the token is in a format no longer supported by the platform.")
    try:
        public_key_str = get_tenant_config(token_tenant_id)['public_key']
    except errors.BaseTapisError:
        raise errors.AuthenticationError("Unable to process Tapis token; unexpected tenant_id.")
    except KeyError:
        raise errors.AuthenticationError("Unable to process Tapis token; no public key associated with the "
                                         "tenant_id.")
    logger.debug(f"public_key_str: {public_key_str}")
    try:
        return jwt.decode(token, public_key_str, algorithm='RS256')
    except Exception as e:
        logger.debug(f"Got exception trying to decode token; exception: {e}")
        raise errors.AuthenticationError("Invalid Tapis token.")

def get_pub_rsa_key(pub_key):
    """
    Return the RSA public key object associated with the string `pub_key`.
    :param pub_key:
    :return:
    """
    return RSA.importKey(pub_key)
