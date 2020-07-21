# flaskbase

Core Python library for building Tapis v3 APIs using Python/flask. This library provides Python modules, Dockerfiles
and build scripts to standardize and streamline the development process.

## Writing a New Service

### Getting Started
When creating a new Tapis v3 service, use the following guidelines:

* Create a git repository with the following:
```
  + service: directory for API source code.
  + migrations: directory for migration scripts.
  - config-local.json: API config values for local development
  - configschema.json: jsonschema definition of the API config.
  - Dockerfile: Build recipe for the API service Docker image.
  - Dockerfile-migrations: Build recipe for the API service migrations Docker image.
  - requirements.txt: Packages required for the API service or migrations scripts.
  - docker-compose.yml: compose file for local development.
  - CHANGELOG.md: Tracks releases for the service.
  - README.md: High level description of the service.
  - service.log: Mount into the API container to capture service logs during local development.
```
* Service configuration - A description of all possible service configurations should be provided
in the configschema.json file. For example, if your service requires a SQL database, you may have 
a property, `sql_db_url`, with the following definition in your configschema.json:
```
    "sql_db_url": {
      "type": "string",
      "description": "full URL, including protocol and database, to the SQL db.",
      "default": "postgres://myservice:mypassword@postgres:5432/mydb"
    },

```
The fields you define in your service's configschema.json file will complement those defined in the 
configschema.json file included in this repository. Any configs that will be used by all services, such as 
`service_password`, should be defined in the common configschema.json. It is currently possible to override the 
definition of a config provided in this repository with a new definition provided in your service's configschema.json
file, but this is not recommended. 

Provide values for the configs in the config-local.json file. When deploying to a remote environment, such as the Tapis
develop environment, the config-local.json can be replaced with file mounted from a ConifgMap with different values.

* Add any packages required by your service to the `requirements.txt` file. Keep in mind that a number of packages are
installed by this repository (such as flask, jsonschema, pyjwt, etc.), so it is possible you will need to add few 
additional packages.

* Create a Dockerfile to build your service. The image name for your service should be `tapis/<service_name>-api`; for
example, `tapis/tokens-api` or `tapis/tenants-api`. Here is a general template for the Dockerfile for your service:

```
  # inherit from the flaskbase image:
  FROM: tapis/flaskbase

  # set the name of the api, for use by some of the common modules.
  ENV TAPIS_API <api_name>

  # install additional requirements for the service
  COPY requirements.txt /home/tapis/requirements.txt
  RUN pip install -r /home/tapis/requirements.txt

  # copy service source code
  COPY configschema.json /home/tapis/configschema.json
  COPY config-local.json /home/tapis/config.json
  COPY service /home/tapis/service

  # run service as non-root tapis user
  RUN chown -R tapis:tapis /home/tapis
  USER tapis

``` 

* For services using Postgres, create migration skeleton. Migrations are based on the `alembic` package and must be 
initialized. Run the following commands from a terminal: 

```
  $ docker run -it --entrypoint=bash --network=<service>-api_<service> -v $(pwd):/home/tapis/mig tapis/tenants-api
  # inside the container:
  $ cd mig; flask db init
  $ flask db migrate
  $ flask db upgrade
  $ exit
```

* Create Dockerfile-migrations to containerize your migrations code. For simple cases, you may be able to just use the 
following after change `<service>` to the name of your service. 

```
# image: tapis/<service>-api-migrations
from tapis/<service>-api

COPY migrations /home/tapis/migrations

ENTRYPOINT ["flask", "db"]
```
* Write a docker-compose.yml file to facilitate local development.

### Using the flaskbase Modules in your Service Code
Code for a number of common tasks has been packaged into the flaskbase modules. In this section, we give an overview of 
how to use some of the functionality in your service.

 * Accessing flaskbase modules:
 The modules in this repository are added to the Python path under the package `common`. Services can import modules 
 directly from this package; for example:
 ```
from common import auth
from common.utils import ok
``` 

* Service configuration and initialization:
Most services will need to do some initialization tasks before they are ready to respond to requests. For example, they 
may need to connect to a database or make some requests to some other Tapis services. Initialization also usually 
involves reading configuration data. The common package audits the supplied config file and makes configration data 
available through a singelton object, `conf`, available from the `common.config` package. By importing the object, for 
instance, in the API's `__init__.py` module, the config file will be read and validated, and the resulting configurations
transformed to Python objects. For example, if a service requires a configuration, `max_number_retries`, then it could
use the following entry in its configschema.json file: 
```
    "max_number_retries": {
      "type": "integer",
      "description": "Maximum number of times the service should retry some complicated logic...",
    },
    . . . # additional properties 
  },
 "required": ["max_number_retries", . . .]
```
and then, place the following code in its `__init__.py` file:
```
from common.config import conf

print(f"We'll be trying at most {conf.max_number_retries} times."
```
By the time the import has completed, the service is guaranteed that `conf` contains all required fields and that they
conform to the requirements specified in the configschema.json file. In particular, the types of the attributes are the
same as that specified in the configchema.json file.

* Making Service Requests:
The `common.auth` package provides a function, `get_service_tapy_client` which can be used to get
a pre-configured Tapis client for making service requests. A common technique is to fetch the service client in the
`__init__.py` module so that it is created at service initialization and available via import throughout the rest
of the service code. 

Within `__init__.py`:
```
from common.auth import get_service_tapy_client
t = get_service_tapy_client()
```
From within any other service module:
```
from service import t
. . . 
# use the client within some method or function:
t.sk.getUsersWithRole(...)
```

* Authentication:
The `common.auth` module provides functions for resolving the authentication data contained in a reqeust to your
service. 

 * JWT Authentication:
The most common and straight-forward case is when an endpoint in your service requires a JWT. For this use case,
the `common.auth.authentication()` function can be used. This function does the following:
   1. Checks for a JWT in the `X-Tapis-Token` header, and checks the other `X-Tapis-` headers.
   2. Validates the JWT, including checking the signature and expiration, and sets the following on the flask thread-local, `g`:
      1. `g.x_tapis_token` - the raw JWT.
      2. `g.token_claims` - the claims object associates with the JWT, as a python dictionary.
      3. `g.username` - the username from the JWT `username` claim.
      4. `g.tenant_id` - the tenant id from the JWT `tenant_id` claim.
      5. `g.account_type` - the account type (either `user` or `service`) from the JWT.
      6. `g.delegation` - whether the token was a delegation token (True or False).
      7. `g.x_tapis_tenant` - the value of the `X-Tapis-Tenant` header.
      8. `g.x_tapis_user` - the value of hte `X-Tapis-User` header.
      
This function raises the following exceptions:
  1. `common.errors.NoTokenError` - if no token was found.
  2. `common.errors.AuthenticationError` - the token was invalid.
  
  * Other Types of Authentication:
  Some services, such as the Authenticator, use other types of authentication, including HTTP
  Basic Auth. Several `common.auth` functions are provided to facilitate tasks related to 
  alternative authentication methods. TODO
  
* Logging:
The `common.logs` module provides basic logger with a file and stdout handler.
To use it, create an instance of the logger in each module where you want to add logs
by calling the `get_logger` function with the module name; for example:

```
from common.logs import get_logger
logger = get_logger(__name__)
```
Then add log statements using the logger:
```
logger.debug(f"some debug message, x={x}."
```

* Error Handling:
For REST APIs, the `common.util` module provides the `TapisApi` class and the `flask_errors_dict` dict and `handle_error()` function. 
Use them by adding the following to your `api.py` module:
```
from flask import Flask
from common.utils import TapisApi, handle_error, flask_errors_dict

# basic flask "app" object:
app = Flask(__name__)

# TapisApi object; created with the app object and the flask_errors_dict to establish the 4 stanza structure of error respones: 
api = TapisApi(app, errors=flask_errors_dict)

# Set up error handling to use the handle_error() function - 
api.handle_error = handle_error
api.handle_exception = handle_error
api.handle_user_exception = handle_error

```

Now, from within a controller, raise an exception of type `common.errors.BaseTapisError` (or any child class). When 
instantiating the exception to be raised, set values for the `msg` and `code` attributed to set the 
message and HTTP response code. For example, in your controller, you could have:
```
   raise errors.MyServiceError(msg='Invalid sprocket; too many widgets.', code=400)
``` 

Then, as long as the `errors.MyServiceError` class descended from the `common.errors.BaseTapisError`, the
HTTP response returned to the user would be:
```
{
    "message": "Invalid sprocket; too many widgets.",
    "status": "error",
    "version": conf.version,    # <-- from your config
    "result": Null
}
``` 
And the HTTP status code would be 400.

Note that if your code (and, by extension, any code your code calls) raises an exception that does not descend
from the `common.errors.BaseTapisError` then the HTTP response will still contain the 4-stanza JSON response above
but the `message` field will contain "Unrecognized exception type.." to indicate that the exception was not a recognized
exception. In general, your service should not raise exceptions of types other than `common.errors.BaseTapisError` and
should instead handle all other exceptions and convert them to the appropriate Tapis Exceptions. This includes all
exceptions from the Python standard library, such as KeyError, AttributeError, etc.

For example, if code you are writing could raise a KeyError, you should catch that and then translate it appropriately.
Of course, different KeyErrors in different situations could translate into a user error, a service error, etc.

```
try:
    app_id = post_data['app_id']
except KeyError:
    raise errors.BadInputError(msg='The app_id paramter was missing. Please be sure to pass app_id.')   # <- decends from BaseTapisError
``` 