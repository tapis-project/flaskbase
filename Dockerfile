# image: tapis/flaskbase
# Base image for building Tapis API services in Python/flask
from python:3.7

RUN useradd tapis
ADD requirements.txt /home/tapis/common-requirements.txt

RUN pip install -U --no-cache-dir pip && \
    pip install --no-cache-dir -r /home/tapis/common-requirements.txt

# TODO -- eventually remove this
RUN apt-get update && apt-get install -y vim

# ----Add the common lib (eventually this could be a pip install)
COPY common /usr/local/lib/python3.7/site-packages/common

# set default threads for gunicorn
ENV threads=3
# set the FLASK_APP var to point to the api.py module in the default location
ENV FLASK_APP service/api.py

WORKDIR /home/tapis

COPY service_entry.sh /home/tapis/entry.sh
RUN chmod +x /home/tapis/entry.sh

CMD ["./entry.sh"]


