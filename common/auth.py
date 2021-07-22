import datetime
import sys
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
                             resource_set='tapipy', #todo -- change back to resource_set='tapipy'
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
    # if there is no base_url the primary_site_admin_tenant_base_url configured for the service:
    if not base_url:
        base_url = conf.primary_site_admin_tenant_base_url
    if not tenant_id:
        tenant_id = conf.service_tenant_id
    if not tenants:
        # the following would work to reference this module's tenants object, but we'll choose to raise
        # an error instead; it could be that
        # tenants = sys.modules[__name__].tenants
        raise errors.BaseTapisError("As a Tapis service, passing in the appropriate tenants manager object"
                                    "is required.")
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
        self.primary_site = None
        self.service_running_at_primary_site = None
        # this timedelta determines how frequently the code will refresh the tenants_cashe, looking for updates
        # to the tenant definition. note that this configuration guarantees it will not refresh any MORE often than
        # the configuration -- it only refreshes when it encoutners a tenant it does not recognize or it fails
        # to validate the signature of an access token
        self.update_tenant_cache_timedelta = datetime.timedelta(seconds=90)
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
        # the tenants service is a special case, as it must be a) configured to serve all tenants and b) actually
        # maintains the list of tenants in its own DB. in this case, we call a special method to use the tenants service
        # code that makes direct db access to get necessary data.
        if conf.service_name == 'tenants':
            self.service_running_at_primary_site = True
            self.last_tenants_cache_update = datetime.datetime.now()
            result = self.get_tenants_for_tenants_api()
            return result
        else:
            logger.debug("this is not the tenants service; calling tenants API to get sites and tenants...")
            # if this case, this is not the tenants service, so we will try to get
            # the list of tenants by making API calls to the tenants service.
            # NOTE: we intentionally create a new Tapis client with *no authentication* so that we can call the Tenants
            # API even _before_ the SK is started up. If we pass a JWT, the Tenants will try to validate it as part of
            # handling our request, and this validation will fail if SK is not available.
            t = Tapis(base_url=conf.primary_site_admin_tenant_base_url, resource_set='local') # TODO -- remove resource_set='local'
            try:
                self.last_tenants_cache_update = datetime.datetime.now()
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
                        self.primary_site = s
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
        tenants = []
        result = []
        logger.info("calling the tenants api's get_sites() function...")
        try:
            sites = tenants_api_get_sites()
        except Exception as e:
            logger.info(
                "WARNING - got an exception trying to compute the sites.. "
                "this better be the tenants migration container.")
            return tenants
        logger.info("calling the tenants api's get_tenants() function...")
        try:
            tenants = tenants_api_get_tenants()
        except Exception as e:
            logger.info(
                "WARNING - got an exception trying to compute the tenants.. "
                "this better be the tenants migration container.")
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
                    self.primary_site = TapisResult(**s)
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
                base_url_at_primary_site = self.get_base_url_for_tenant_primary_site(tenant.tenant_id)
                if base_url_at_primary_site in url:
                    return tenant
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

    def get_base_url_admin_tenant_primary_site(self):
        """
        Returns the base URL for the admin tenants of the primary site.
        :return:
        """
        admin_tenant_id = self.primary_site.site_admin_tenant_id
        return self.get_tenant_config(tenant_id=admin_tenant_id).base_url

    def get_site_and_base_url_for_service_request(self, tenant_id, service):
        """
        Returns the site_id and base_url that should be used for a service request based on the tenant_id and the
        service to which the request is targeting.

        `tenant_id` should be the tenant that the object(s) of the request live in (i.e., the value of the
        X-Tapis-Tenant header).  Note that in the case of service=tenants, the value of tenant_id id now
        well defined and is ignored.

        `service` should be the service being requested (e.g., apps, files, sk, tenants, etc.)

        """
        logger.debug(f"top of get_site_and_base_url_for_service_request() for tenant_id: {tenant_id} and service: {service}")
        site_id_for_request = None
        base_url = None
        # requests to the tenants service should always go to the primary site
        if service == 'tenants':
            site_id_for_request = self.primary_site.site_id
            base_url =self.get_base_url_admin_tenant_primary_site()
            logger.debug(f"call to tenants API, returning site_id: {site_id_for_request}; base url: {base_url}")
            return site_id_for_request, base_url

        # the SK and token services always use the same site as the site the service is running on --
        tenant_config = self.get_tenant_config(tenant_id=tenant_id)
        if service == 'sk' or service == 'security' or service == 'tokens':
            site_id_for_request = conf.service_site_id
            # if the site_id for the service is the same as the site_id for the request, use the tenant URL:
            if conf.service_site_id == tenant_config.site_id:
                base_url = tenant_config.base_url
                logger.debug(f"service '{service}' is SK or tokens and tenant's site was the same as the "
                             f"configured site; returning site_id: {site_id_for_request}; base_url: {base_url}")
                return site_id_for_request, base_url
            else:
                # otherwise, we use the primary site (NOTE: if we are here, the configured site_id is different from the
                # tenant's owning site. this only happens when the running service is at the primary site; services at
                # associate sites never handle requests for tenants they do not own.
                site_id_for_request = self.primary_site.site_id
                base_url = self.get_base_url_for_tenant_primary_site(tenant_id)
                logger.debug(f'request for {tenant_id} and {service}; returning site_id: {site_id_for_request}; '
                             f'base URL: {base_url}')
                return site_id_for_request, base_url
        # if the service is hosted by the site, we use the base_url associated with the tenant --
        try:
            # get the services hosted by the owning site of the tenant
            site_services = tenant_config.site.services
        except AttributeError:
            logger.info("tenant_config had no site or services; setting site_service to [].")
            site_services = []
        if service in site_services:
            site_id_for_request = conf.service_site_id
            base_url = tenant_config.base_url
            logger.debug(f"service {service} was hosted at site; returning site_id: {site_id_for_request}; "
                         f"tenant's base_url: {base_url}")
            return site_id_for_request, base_url
        # otherwise, we use the primary site
        site_id_for_request = self.primary_site.site_id
        base_url = self.get_base_url_for_tenant_primary_site(tenant_id)
        logger.debug(f'request was for {tenant_id} and {service}; returning site_id: {site_id_for_request};'
                     f'base URL: {base_url}')
        return site_id_for_request, base_url

    def get_base_url_for_tenant_primary_site(self, tenant_id):
        """
        Compute the base_url at the primary site for a tenant owned by an associate site.
        """
        try:
            base_url_template = self.primary_site.tenant_base_url_template
        except AttributeError:
            raise errors.BaseTapisError(
                f"Could not compute the base_url for tenant {tenant_id} at the primary site."
                f"The primary site was missing the tenant_base_url_template attribute.")
        return base_url_template.replace('${tenant_id}', tenant_id)

    def get_site_admin_tenants_for_service(self):
        """
        Get all tenants for which this service might need to interact with.
        """
        # services running at the primary site must interact with all sites, so this list comprehension
        # just pulls out the tenant's that are admin tenant id's for some site.
        logger.debug("top of get_site_admin_tenants_for_service")
        if self.service_running_at_primary_site:
            admin_tenants = [t.tenant_id for t in self.tenants if t.tenant_id == t.site.site_admin_tenant_id]
        # otherwise, this service is running at an associate site, so it only needs itself and the primary site.
        else:
            admin_tenants = [conf.service_tenant_id]
            for t in self.tenants:
                if t.tenant_id == t.site.site_admin_tenant_id and hasattr(t.site, 'primary') and t.site.primary:
                    admin_tenants.append(t.tenant_id)
        logger.debug(f"site admin tenants for service: {admin_tenants}")
        return admin_tenants

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
            return
        else:
            raise e
    resolve_tenant_id_for_request(tenants)

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
    Resolves the tenant associated with the request and sets it on the g.request_tenant_id variable. Additionally,
    sets the g.request_tenant_base_url variable in the process. Returns the request_tenant_id (string).

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
    # if the x_tapis_tenant header was set, then this must be a request from a service account. in this case, the
    # request_tenant_id will in general not match the tapis/tenant_id claim in the service token.
    if g.x_tapis_tenant and g.x_tapis_token:
        logger.debug("found x_tapis_tenant and x_tapis_token on the g object.")
        # need to check token is a service token
        if not g.token_claims.get('tapis/account_type') == 'service':
            raise errors.PermissionsError('Setting X-Tapis-Tenant header and X-Tapis-Token requires a service token.')
        # validation has passed, so set the request tenant_id to the x_tapis_tenant:
        g.request_tenant_id = g.x_tapis_tenant
        request_tenant = tenants.get_tenant_config(tenant_id=g.request_tenant_id)
        g.request_tenant_base_url = request_tenant.base_url
        # todo -- compute and set g.request_site_id
        return g.request_tenant_id
    # in all other cases, the request's tenant_id is based on the base URL of the request:
    logger.debug("computing base_url based on the URL of the request...")
    flask_baseurl = request.base_url
    logger.debug(f"flask_baseurl: {flask_baseurl}")
    # the flask_baseurl includes the protocol, port (if present) and contains the url path; examples:
    #  http://localhost:5000/v3/oauth2/tenant;
    #  https://dev.develop.tapis.io/v3/oauth2/tenant
    # in the local development case, the base URL (e.g., localhost:5000...) cannot be used to resolve the tenant id
    # so instead we use the tenant_id claim within the x-tapis-token:
    if 'http://172.17.0.1:' in flask_baseurl or 'http://localhost:' in flask_baseurl:
        logger.warn("found 172.17.0.1 or localhost in flask_baseurl; we are assuming this is local development!!")
        # some services, such as authenticator, have endpoints that do not receive tokens. in the local development
        # case for these endpoints, we don't have a lot of good options -- we can't use the base URL or the token
        # to determine the tenant, so we just set it to the "dev" tenant.
        if not hasattr(g, 'token_claims'):
            logger.warn("did not find a token_claims attribute in local development case. Can't use the URL, can't"
                        "use the token. We have no option but to set the tenant to dev!!")
            g.request_tenant_id = 'dev'
            g.request_tenant_base_url = 'http://dev.develop.tapis.io'
            return g.request_tenant_id
        request_tenant = tenants.get_tenant_config(tenant_id=g.token_claims.get('tapis/tenant_id'))
        g.request_tenant_id = request_tenant.tenant_id
        g.request_tenant_base_url = request_tenant.base_url
        # todo -- compute and set g.request_site_id
        return g.request_tenant_id
    # otherwise we are not in the local development case, so use the request's base URL to determine the tenant id
    # and make sure that tenant_id matches the tenant_id claim in the token.
    request_tenant = tenants.get_tenant_config(url=flask_baseurl)
    g.request_tenant_id = request_tenant.tenant_id
    g.request_tenant_base_url = request_tenant.base_url
    # todo -- compute and set g.request_site_id
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
    # user tokens must *not* set the X-Tapis-Tenant and X-Tapis_user headers
    else:
        try:
            if g.x_tapis_tenant or g.x_tapis_user:
                raise errors.AuthenticationError("Invalid request; cannot set OBO headers with a user token.")
        except AttributeError:
            pass
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
    tries = 0
    while tries < 2:
        tries = tries + 1
        try:
            claims = jwt.decode(token, public_key_str)
        except Exception as e:
            # if we get an exception decoding it could be that the tenant's public key has changed (i.e., that
            # the public key in out tenant_cache is stale. if we haven't updated the tenant_cache in the last
            # update_tenant_cache_timedelta then go ahead and update and try the decode again.
            if ( (datetime.datetime.now() > tenants.last_tenants_cache_update + tenants.update_tenant_cache_timedelta)
                    and tries == 1):
                tenants.get_tenants()
                continue
            # otherwise, we were using a recent public key, so just fail out.
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
    # the X-Tapis-* (OBO) headers are required for service requests; if it is not set, raise an error.
    if not g.x_tapis_tenant:
        raise errors.AuthenticationError("Invalid service request; X-Tapis-Tenant header missing.")
    if not g.x_tapis_user:
        raise errors.AuthenticationError("Invalid service request; X-Tapis-User header missing.")
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