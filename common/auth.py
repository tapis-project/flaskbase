import base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

from flask import g, request
import jwt
from tapipy.tapis import Tapis, TapisResult

from common.config import conf
from common import errors
from common.logs import get_logger
logger = get_logger(__name__)

def get_service_tapis_client(tenant_id=None,
                             base_url=None,
                             jwt=None,
                             # TODO -- revert once resouces are up oresource_setn github!!!!
                             # resource_set='tapipy',
                             resource_set='local',
                             custom_spec_dict=None,
                             download_latest_specs=False,
                             tenants=None):
    """
    Returns a Tapis client for the service using the service's configuration. If tenant_id is not passed, uses the first
    tenant in the service's tenants configuration.
    :param tenant_id: (str) The tenant_id associated with the tenant to configure the client with.
    :param base_url: (str) The base URL for the tenant to configure the client with.
    :return: (tapipy.tapis.Tapis) A Tapipy client object.
    """
    # if there is no base_url the primary_site_master_tenant_base_url configured for the service:
    if not base_url:
        base_url = conf.primary_site_master_tenant_base_url
    if not tenant_id:
        tenant_id = conf.service_tenant_id
    t = Tapis(base_url=base_url,
              tenant_id=tenant_id,
              username=conf.service_name,
              account_type='service',
              service_password=conf.service_password,
              jwt=jwt,
              resource_set=resource_set,
              custom_spec_dict=custom_spec_dict,
              download_latest_specs=download_latest_specs,
              tenants=tenants,
              is_tapis_service=True)
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
        # if this is the first time we are calling get_tenants, set the service_running_at_primary_site attribute.
        if not hasattr(self, "service_running_at_primary_site"):
            self.service_running_at_primary_site = False
        sites = []
        tenants = []
        # the tenants service is a special case, as it must be a) configured to serve all tenants and b) actually maintains
        # the list of tenants in its own DB. in this case, we return the empty list since the tenants service will use direct
        # db access to get necessary data.
        if conf.service_name == 'tenants':
            self.service_running_at_primary_site = True
            return self.get_tenants_for_tenants_api()
        else:
            logger.debug("this is not the tenants service; calling tenants API to get sites and tenants...")
            # if we are here, this is not the tenants service, so we will try to get
            # the list of tenants directly from the tenants service.
            # NOTE: we intentionally create a new Tapis client with *no authentication* so that we can call the Tenants
            # API even _before_ the SK is started up. If we pass a JWT, the Tenants will try to validate it as part of
            # handling our request, and this validation will fail if SK is not available.
            t = Tapis(base_url=conf.primary_site_master_tenant_base_url, resource_set='local') # TODO -- remove resource_set='local'
            try:
                tenants = t.tenants.list_tenants()
                sites = t.tenants.list_sites()
            except Exception as e:
                msg = f"Got an exception trying to get the list of sites and tenants. Exception: {e}"
                logger.error(msg)
                raise errors.BaseTapisError("Unable to retrieve sites and tenants from the Tenants API.")
            for t in tenants:
                self.extend_tenant(t)
                for s in sites:
                    if hasattr(s, "primary") and s.primary:
                        self.primry_site = s
                        if s.site_id == conf.service_site_id:
                            logger.debug(f"this service is running at the primary site: {s.site_id}")
                            self.service_running_at_primary_site = True
                    if s.site_id == t.site_id:
                        t.site = s
            return tenants

    def get_tenants_for_tenants_api(self):
        """
        This method computes the tenants and sites for the tenants service only. Note that the tenants service is a
        special case because it must retrieve the sites and tenants from its own DB, not from
        """
        logger.debug("this is the tenants service, pulling sites and tenants from db...")
        # NOTE: only in the case of the tenants service will we be able to import this function; so this import needs to
        # stay guarded in this method.
        if not conf.service_name == 'tenants':
            raise errors.BaseTapisError("get_tenants_for_tenants_api called by a service other than tenants.")
        from service.models import get_tenants as tenants_api_get_tenants
        from service.models import get_sites as tenants_api_get_sites
        # in the case where the tenants api migrations are running, this call will fail with a sqlalchemy.exc.ProgrammingError
        # because the tenants table will not exist yet.
        sites = []
        tenants = []
        result = []
        logger.info("calling the tenants api's get_sites() function...")
        try:
            sites = tenants_api_get_sites()
        except Exception as e:
            logger.info(
                "WARNING - got an exception trying to compute the sites.. this better be the tenants migration container.")
            return tenants
        logger.info("calling the tenants api's get_tenants() function...")
        try:
            tenants = tenants_api_get_tenants()
        except Exception as e:
            logger.info(
                "WARNING - got an exception trying to compute the tenants.. this better be the tenants migration container.")
            return tenants
        # for each tenant, look up its corresponding site record and save it on the tenant record--
        for t in tenants:
            # Remove datetime objects --
            t.pop('create_time')
            t.pop('last_update_time')
            # convert the tenants to TapisResult objects, and then append the sites object.
            tn = TapisResult(**t)
            for s in sites:
                if 'primary' in s.keys() and s['primary']:
                    self.primry_site = TapisResult(**s)
                if s['site_id'] == tn.site_id:
                    tn.site = TapisResult(**s)
                    result.append(tn)
                    break
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
                try:
                    if tenant.tenant_id == tenant_id:
                        logger.debug(f"found tenant {tenant_id}")
                        return tenant
                except TypeError as e:
                    logger.error(f"caught the type error: {e}")
            logger.info(f"did not find tenant: {tenant_id}. self.tenants: {self.tenants}")
            return None

        def find_tenant_from_url():
            for tenant in self.tenants:
                if tenant.base_url in url:
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
        logger.debug(f"did not find tenant; going to reload tenants.")
        self.reload_tenants()
        logger.debug(f"tenants reloaded. Tenants list is now: {tenants.tenants}")
        if tenant_id:
            t = find_tenant_from_id()
        elif url:
            t = find_tenant_from_url()
        if t:
            return t
        raise errors.BaseTapisError("invalid tenant id.")

    def get_base_url_for_service_request(self, tenant_id, service):
        """
        Get the base_url that should be used for a service request based on the tenant_id and the service
        that to which the request is targeting.
        """
        logger.debug(f"top of get_base_url_for_service_request() for tenant_id: {tenant_id} and service: {service}")
        tenant_config = self.get_tenant_config(tenant_id=tenant_id)
        try:
            # get the services hosted by the owning site of the tenant
            site_services = tenant_config.site.services
        except AttributeError:
            logger.info("tenant_config had no site or services; setting site_service to [].")
            site_services = []
        # the SK and token services always use the same site as the site the service is running on --
        if service == 'sk' or service == 'security' or service == 'tokens':
            # if the site_id for the service is the same as the site_id for the request, use the tenant URL:
            if conf.service_site_id == tenant_config.site_id:
                base_url = tenant_config.base_url
                logger.debug(f"service {service} was SK or tokens and tenant's site was the same as the configured site; "
                             f"returning tenant's base_url: {base_url}")
            else:
                # otherwise, we use the primary site (NOTE: if we are here, the configured site_id is different from the
                # tenant's owning site. this only happens when the running service is at the primary site; services at
                # associate sites never handle requests for tenants they do not own.
                try:
                    base_url_template = self.primry_site.tenant_base_url_template
                except AttributeError:
                    raise errors.BaseTapisError(
                        f"Could not compute the base_url for tenant {tenant_id} at the primary site."
                        f"The primary site was missing the tenant_base_url_template attribute.")
                base_url = base_url_template.replace('${tenant_id}', tenant_id)
                logger.debug(f'base_url for {tenant_id} and {service} was: {base_url}')
                return base_url
        # if the service is hosted by the site, we use the base_url associated with the tenant --
        if service in site_services:
            base_url = tenant_config.base_url
            logger.debug(f"service {service} was hosted at site; returning tenant's base_url: {base_url}")
            return base_url
        # otherwise, we use the primary site
        try:
            base_url_template = self.primry_site.tenant_base_url_template
        except AttributeError:
            raise errors.BaseTapisError(f"Could not compute the base_url for tenant {tenant_id} at the primary site."
                                        f"The primary site was missing the tenant_base_url_template attribute.")
        base_url = base_url_template.replace('${tenant_id}', tenant_id)
        logger.debug(f'base_url for {tenant_id} and {service} was: {base_url}')
        return base_url

    def get_site_master_tenants_for_service(self):
        """
        Get all tenants for which this service might need to interact with.
        """
        # services running at the primary site must interact with all sites, so this list comprehension
        # just pulls out the tenant's that are master tenant id's for some site.
        logger.debug("top of get_site_master_tenants_for_service")
        if self.service_running_at_primary_site:
            master_tenants = [t.tenant_id for t in self.tenants if t.tenant_id == t.site.site_master_tenant_id]
        # otherwise, this service is running at an associate site, so it only needs itself and the primary site.
        else:
            master_tenants = [conf.service_tenant_id]
            for t in self.tenants:
                if t.tenant_id == t.site.site_master_tenant_id and hasattr(t.site, 'primary') and t.site.primary:
                    master_tenants.append(t.tenant_id)
        logger.debug(f"site master tenants for service: {master_tenants}")
        return master_tenants

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
    If the X-Tapis-Token is provided in this case, it must be a service token. The Tapis service should validate
    aspects of service token usage by calling the validate_request_token() function.
    2) If the X-Tapis-Tenant header is not set, then the base_url for this request dictates the tenant_id. There
    are two sub-cases:
      2a) The base_url is the tenant's base URL, in which case the base_url will be in the tenant list,
      2b) The base_url is the tenant's primary-site URL (this is the case when the associate site has forwarded
          a request to the primary site) in which case the base_url will be of the form <tenant_id>.tapis.io
      cf., https://confluence.tacc.utexas.edu/display/CIC/Authentication+Subsystem
    :return:
    """
    logger.debug("top of resolve_tenant_id_for_request")
    add_headers()
    if g.x_tapis_tenant and g.x_tapis_token:
        logger.debug("found x_tapis_tenant and x_tapis_token on the g object.")
        # need to check token is a service token
        if not g.token_claims.get('tapis/account_type') == 'service':
            raise errors.PermissionsError('Setting X-Tapis-Tenant header and X-Tapis-Token requires a service token.')
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
    # set basic variables on the flask thread-local
    g.token_claims = claims
    g.username = claims.get('tapis/username')
    g.tenant_id = claims.get('tapis/tenant_id')
    g.account_type = claims.get('tapis/account_type')
    g.delegation = claims.get('tapis/delegation')
    # service tokens have some extra checks:
    if claims.get('tapis/account_type') == 'service':
        g.site_id = claims.get('tapis/target_site_id')
        logger.debug(f"service account; setting g.site_id: {g.site_id}; g.tenant_id: {g.tenant_id}; g.username: {g.username}")
        service_token_checks(claims, tenants)
    else:
        logger.debug(f"not a service account; setting g.tenant_id: {g.tenant_id}; g.username: {g.username}")


def validate_token(token, tenants=tenants):
    """
    Stand-alone function to validate a Tapis token. 
    :param token: The token to validate
    :param tenants: The service's tenants object with tenant configs; Should be an instance of Tenants.
    :return: 
    """
    # first, decode the token data to determine the tenant associated with the token. We are not able to
    # check the signature until we know which tenant, and thus, which public key, to use for validation.
    logger.debug("top of validate_token")
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
        token_tenant = tenants.get_tenant_config(tenant_id=token_tenant_id)
        public_key_str = token_tenant.public_key
    except errors.BaseTapisError:
        logger.error(f"Did not find the public key for tenant_id {token_tenant_id} in the tenant configs.")
        raise errors.AuthenticationError("Unable to process Tapis token; unexpected tenant_id.")
    except AttributeError:
        raise errors.AuthenticationError("Unable to process Tapis token; no public key associated with the "
                                         "tenant_id.")
    if not public_key_str:
        raise errors.AuthenticationError("Could not find the public key for the tenant_id associated with the tenant.")
    # check signature and decode
    try:
        claims = jwt.decode(token, public_key_str)
    except Exception as e:
        logger.debug(f"Got exception trying to decode token; exception: {e}")
        raise errors.AuthenticationError("Invalid Tapis token.")
    # if the token is a service token (i.e., this is a service to service request), do additional checks:
    return claims

def get_pub_rsa_key(pub_key):
    """
    Return the RSA public key object associated with the string `pub_key`.
    :param pub_key:
    :return:
    """
    return RSA.importKey(pub_key)


def service_token_checks(claims, tenants):
    """
    This function does additional checks when a service token is used to make a Tapis request.

    """
    logger.debug(f"top of service_token_checks; claims: {claims}")
    # first check that the target_site claim in the token matches this service's site_id --
    target_site_id = claims.get('tapis/target_site')
    try:
        service_site_id = conf.service_site_id
    except AttributeError:
        msg = "service configured without a site_id. Aborting."
        logger.error(msg)
        raise errors.BaseTapisError(msg)
    if not target_site_id == service_site_id:
        msg = f"token's target_site ({target_site_id}) does not match service's site_id ({service_site_id}."
        logger.info(msg)
        raise errors.AuthenticationError("Invalid service token; "
                                         "target_site claim does not match this service's site_id.")
    # check that this service should be fulfilling this request based on its site_id config --
    # the X-Tapis-Tenant header is required for service requests; if it is not set, raise an error.
    if not g.x_tapis_tenant:
        raise errors.AuthenticationError("Invalid service request; X-Tapis-Tenant header missing.")
    request_tenant = tenants.get_tenant_config(tenant_id=g.x_tapis_tenant)
    site_id_for_request = request_tenant.site_id
    # if the service's site_id is the same as the site for the request, the request is always allowed:
    if service_site_id == site_id_for_request:
        logger.debug("request is for the same site as the service; allowing request.")
        return True
    # otherwise, we only allow the primary site to handle requests for other sites, and only if the service is NOT
    # on the site's list of services that it runs.
    if not tenants.service_running_at_primary_site:
        raise errors.AuthenticationError("Cross-site service requests are only allowed to the primary site.")
    logger.debug("this service is running at the primary site.")
    # make sure this service is not on the list of services deployed at the associate site --
    if conf.service_name in request_tenant.site.services:
        raise errors.AuthenticationError(f"The primary site does not handle requests to service {conf.service}")
    logger.debug("this service is NOT in the JWT tenant's owning site's set of services. allowing the request.")