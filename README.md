# flaskbase

Core Python library for building Tapis v3 APIs using Python/flask. This library provides Python modules, Dockerfiles
and build scripts to standardize and streamline the development process.

## Getting Started

1. Create a git repository with the following:

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

2. Edit the Dockerfile:

```
  # inherit from the flaskbase
  FROM: tapis/flaskbase

  # set the name of the api, for use by 
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


3. Create migration skeleton.
  Migrations are based on the `alembic` package and must be initialized.

```
  $ docker run -it --entrypoint=bash --network=<service>-api_<service> -v $(pwd):/home/tapis/mig tapis/tenants-api
  # inside the container:
  $ cd mig; flask db init
  $ flask db migrate
  $ flask db upgrade
  $ exit
```

