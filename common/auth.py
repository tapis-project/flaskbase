import base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

from flask import g, request
import jwt
from tapipy.tapis import Tapis

from common.config import conf
from common import errors
from common.logs import get_logger
logger = get_logger(__name__)

def get_service_tapis_client(tenant_id=None, base_url=None, jwt=None, resource_set='tapipy', custom_spec_dict=None, download_latest_specs=False):
    """
    Returns a Tapis client for the service using the service's configuration. If tenant_id is not passed, uses the first
    tenant in the service's tenants configuration.
    :param tenant_id: (str) The tenant_id associated with the tenant to configure the client with.
    :param base_url: (str) The base URL for the tenant to configure the client with.
    :return: (tapipy.tapis.Tapis) A Tapipy client object.
    """
    # if there is no tenant_id, use the service_tenant_id and service_tenant_base_url configured for the service:
    if not tenant_id:
        tenant_id = conf.service_tenant_id
    if not base_url:
        base_url = conf.service_tenant_base_url
    t = Tapis(base_url=base_url,
              tenant_id=tenant_id,
              username=conf.service_name,
              account_type='service',
              service_password=conf.service_password,
              jwt=jwt,
              resource_set=resource_set,
              custom_spec_dict=custom_spec_dict,
              download_latest_specs=download_latest_specs)
    if not jwt:
        t.get_tokens()
    return t


class Tenants(object):
    """
    Class for managing the tenants available in the tenants registry, including metadata associated with the tenant.
    """
    def __init__(self):
        self.tenants = self.get_tenants()

    def extend_tenant(self, t):
        """
        Method to add additional attributes to tenant object that are specific to a single service, such as the private
        keys for the Tokens API or the LDAP passwords for the authenticator. The service should implement this mwthod
        :param t:
        :return:
        """
        return t

    def get_tenants(self):
        """
        Retrieve the set of tenants and associated data that this service instance is serving requests for.
        :return:
        """
        logger.debug("top of get_tenants()")
        # these are the tenant_id strings configured for the service -
        tenants_strings = conf.tenants
        result = []
        # in dev mode, services can be configured to not use the security kernel, in which case we must get
        # configuration for a "dev" tenant directly from the service configs:
        if not conf.use_tenants:
            logger.debug("use_tenants was False")
            for tenant in tenants_strings:
                t = {'tenant_id': tenant,
                     'iss': conf.dev_iss,
                     'public_key': conf.dev_jwt_public_key,
                     'token_service': conf.dev_token_service,
                     'base_url': conf.dev_base_url,
                     'authenticator': conf.dev_authenticator,
                     'security_kernel': conf.dev_security_kernel,
                     'is_owned_by_associate_site': conf.dev_is_owned_by_associate_site,
                     'allowable_x_tenant_ids': conf.dev_allowable_x_tenant_ids,
                     }
                self.extend_tenant(t)
                result.append(t)
            return result
        # the tenants service is a special case, as it must be a) configured to serve all tenants and b) actually maintains
        # the list of tenants in its own DB. in this case, we return the empty list since the tenants service will use direct
        # db access to get necessary data.
        elif conf.service_name == 'tenants' and tenants_strings[0] == '*':
            logger.debug("this is the tenants service, pulling tenants from db...")
            # NOTE: only in the case of the tenants service will we be able to import this function; so this import needs to
            # stay guarded by the above IF statement.
            from service.models import get_tenants as tenants_api_get_tenants
            # in the case where the tenants api migrations are running, this call will fail with a sqlalchemy.exc.ProgrammingError
            # because the tenants table will not exist yet.
            logger.info("calling the tenants api's get_tenants() function...")
            try:
                result = tenants_api_get_tenants()
                logger.info(f"Got {result} from the tenants API")
                return result
            except Exception as e:
                logger.info(
                    "WARNING - got an exception trying to compute the tenants.. this better be the tenants migration container.")
                return result
        else:
            logger.debug("this is not the tenants service; calling tenants API to get tenants...")
            # if we are here, this is not the tenants service and it is configured to use the tenants API, so we will try to get
            # the list of tenants directly from the tenants service.
            # NOTE: we intentionally create a new Tapis client with *no authentication* so that we can call the Tenants
            # API even _before_ the SK is started up. If we pass a JWT, Tenants will try to
            t = Tapis(base_url=conf.service_tenant_base_url)
            try:
                tenant_list = t.tenants.list_tenants()
            except Exception as e:
                msg = f"Got an exception trying to get the list of tenants. Exception: {e}"
                print(msg)
                logger.error(msg)
                raise errors.BaseTapisError("Unable to retrieve tenants from the Tenants API.")
            if not type(tenant_list) == list:
                logger.error(f"Did not get a list object from list_tenants(); got: {tenant_list}")
            for tn in tenant_list:
                t = {'tenant_id': tn.tenant_id,
                     'iss': tn.token_service,
                     'public_key': tn.public_key,
                     'token_service': tn.token_service,
                     'base_url': tn.base_url,
                     'authenticator': tn.authenticator,
                     'security_kernel': tn.security_kernel,
                     'is_owned_by_associate_site': tn.is_owned_by_associate_site,
                     'allowable_x_tenant_ids': tn.allowable_x_tenant_ids,
                     }
                self.extend_tenant(t)
                logger.debug(f"adding tenant: {t}")
                result.append(t)
        return result

    def reload_tenants(self):
        self.tenants = self.get_tenants()

    def get_tenant_config(self, tenant_id=None, url=None):
        """
        Return the config for a specific tenant_id from the tenants config based on either a tenant_id or a URL.
        One or the other (but not both) must be passed.
        :param tenant_id: (str) The tenant_id to match.
        :param url: (str) The URL to use to match.
        :return:
        """
        def find_tenant_from_id():
            logger.debug(f"top of find_tenant_from_id for tenant_id: {tenant_id}")
            for tenant in self.tenants:
                if tenant['tenant_id'] == tenant_id:
                    return tenant
            logger.info(f"did not find tenant: {tenant_id}. self.tenants: {self.tenants}")
            return None

        def find_tenant_from_url():
            for tenant in self.tenants:
                if tenant['base_url'] in url:
                    return tenant
                # todo - also check the tenant's primary_site_url once that is added to the tenant registry and model...
            return None

        logger.debug(f"top of get_tenant_config; called with tenant_id: {tenant_id}; url: {url}")
        # allow for local development by checking for localhost:500 in the url; note: using 500, NOT 5000 since services
        # might be running on different 500x ports locally, e.g., 5000, 5001, 5002, etc..
        if url and 'http://localhost:500' in url:
            logger.debug("http://localhost:500 in url; resolving tenant id to dev.")
            tenant_id = 'dev'
        if tenant_id:
            logger.debug(f"looking for tenant with tenant_id: {tenant_id}")
            t = find_tenant_from_id()
        elif url:
            logger.debug(f"looking for tenant with url {url}")
            # convert URL from http:// to https://
            if url.startswith('http://'):
                logger.debug("url started with http://; stripping and replacing with https")
                url = url[len('http://'):]
                url = 'https://{}'.format(url)
            logger.debug(f"looking for tenant with URL: {url}")
            t = find_tenant_from_url()
        else:
            raise errors.BaseTapisError("Invalid call to get_tenant_config; either tenant_id or url must be passed.")
        if t:
            return t
        # try one reload and then give up -
        logger.debug(f"did not find tenant; going to reload tenants. Tenants list was: {tenants.tenants}")
        self.reload_tenants()
        logger.debug(f"tenants reloaded. Tenants list is now: {tenants.tenants}")
        if tenant_id:
            t = find_tenant_from_id()
        elif url:
            t = find_tenant_from_url()
        if t:
            return t
        raise errors.BaseTapisError("invalid tenant id.")

# singleton object with all the tenant data and automatic reload functionality.
# services that override the base Tenants class with a custom class that implements the extend_tenant() method should
# create singletons of that child class and not use this object.
tenants = Tenants()


def authn_and_authz(tenants=tenants, authn_callback=None, authz_callback=None):
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
    authentication(tenants, authn_callback)
    authorization(authz_callback)


def authentication(tenants=tenants, authn_callback=None):
    """Entry point for authentication. Use as follows:

    import auth

    my_app = Flask(__name__)
    @my_app.before_request
    def authn_for_my_app():
        auth.authentication()

    """
    add_headers()
    try:
        validate_request_token(tenants)
    except errors.NoTokenError as e:
        if authn_callback:
            authn_callback()
        else:
            raise e

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


def resolve_tenant_id_for_request(tenants=tenants):
    """
    Resolves the tenant associated with the request. Assumes the add_headers() and validate_request_token() functions
    have been called to set attributes on the flask thread-local.

    The high-level algorithm is as follows:

    1) If the X-Tapis-Tenant header is set in the request, this is the tenant_id for the request;
    If the X-Tapis-Token is provided in this case, it must be a service token for a tenant that is allowed
    to set the id in the X-Tapis-Tenant header (i.e., be on the allowable_x_tenant_ids list for the service
    tenant.

    2) If the X-Tapis-Tenant header is not set, then the base_url for this request dictates the tenant_id. There
    are two sub-cases:
      2a) The base_url is the tenant's base URL, in which case the base_url will be in the tenant list,
      2b) The base_url is the tenant's primary-site URL (this is the case when the associate site has forwarded
          a request to the primary site) in which case the base_url will be of the form <tenant_id>.api.tapis.io
      cf., https://confluence.tacc.utexas.edu/display/CIC/Authentication+Subsystem
    :return:
    """
    logger.debug("top of resolve_tenant_id_for_request")
    add_headers()
    if g.x_tapis_tenant and g.x_tapis_token:
        logger.debug("found x_tapis_tenant and x_tapis_token on the g object.")
        # need to check:
        # 1). token is a service token
        # 2). tenant id value for x_tapis_token is in the allowable_x_tenant_ids list for service token tenant_id
        if not g.token_claims.get('tapis/account_type') == 'service':
            raise errors.PermissionsError('Setting X-Tapis-Tenant header and X-Tapis-Token requires a service token.')
        allowable_x_tenant_ids = tenants.get_tenant_config(tenant_id=g.token_claims.get('tenant_id')).get('allowable_x_tenant_ids') or []
        if g.x_tapis_tenant not in allowable_x_tenant_ids:
            raise errors.PermissionsError('X-Tapis-Tenant header value is not allowed for the service token tenant.')
        # validation has passed, so set the request tenant_id to the x_tapis_tenant:
        g.request_tenant_id = g.x_tapis_tenant
        request_tenant = tenants.get_tenant_config(tenant_id=g.request_tenant_id)
        g.request_tenant_base_url = request_tenant['base_url']
        return g.request_tenant_id
    # in all other cases, the request's tenant_id is based on the base URL of the request:
    logger.debug("computing base_url based on the URL of the request...")
    flask_baseurl = request.base_url
    # the flask_baseurl includes the protocol, port (if present) and contains the url path; examples:
    #  http://localhost:5000/v3/oauth2/tenant;
    #  https://dev.develop.tapis.io/v3/oauth2/tenant
    request_tenant = tenants.get_tenant_config(url=flask_baseurl)
    g.request_tenant_id = request_tenant['tenant_id']
    g.request_tenant_base_url = request_tenant['base_url']
    # we need to check that the request's tenant_id matches the tenant_id in the token:
    if g.x_tapis_token:
        logger.debug("found x_tapis_token on g; making sure tenant claim inside token matches that of the base URL.")
        token_tenant_id = g.token_claims.get('tapis/tenant_id')
        if not token_tenant_id == g.request_tenant_id:
            raise errors.PermissionsError(f'The tenant_id claim in the token, '
                                          f'{token_tenant_id} does not match the URL tenant, {g.request_tenant_id}.')
    return g.request_tenant_id


def validate_request_token(tenants=tenants):
    """
    Attempts to validate the Tapis access token in the request based on the public key and signature in the JWT.
    This function raises
        - NoTokenError - if no token is present in the request.
        - AuthenticationError - if validation is not successful.
    :param tenants: The service's tenants object.
    :return:
    """
    if not hasattr(g, 'x_tapis_token'):
        raise errors.NoTokenError("No access token found in the request.")
    claims = validate_token(g.x_tapis_token, tenants)
    g.token_claims = claims
    g.username = claims.get('tapis/username')
    g.tenant_id = claims.get('tapis/tenant_id')
    g.account_type = claims.get('tapis/account_type')
    g.delegation = claims.get('tapis/delegation')
    logger.debug(f"setting g.tenant_id: {g.tenant_id}; g.username: {g.username}")


def validate_token(token, tenants=tenants):
    """
    Stand-alone function to validate a Tapis token. 
    :param token: The token to validate
    :param tenants: The service's tenants object with tenant configs; Should be an instance of Tenants.
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
        public_key_str = tenants.get_tenant_config(tenant_id=token_tenant_id)['public_key']
    except errors.BaseTapisError:
        logger.error(f"Did not find the public key for tenant_id {token_tenant_id} in the tenant configs.")
        raise errors.AuthenticationError("Unable to process Tapis token; unexpected tenant_id.")
    except KeyError:
        raise errors.AuthenticationError("Unable to process Tapis token; no public key associated with the "
                                         "tenant_id.")
    logger.debug(f"public_key_str: {public_key_str}")
    try:
        it = jwt.decode(token, public_key_str)
        logger.debug(f'heyooo: {it}')
        return it
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
