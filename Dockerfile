FROM debian:stretch-slim
MAINTAINER Alexey Nizhegolenko <ratibor78@gmail.com>

COPY requirements.txt /tmp/requirements.txt

RUN \
  apt-get update && \
  apt-get install -y --no-install-recommends uwsgi \
  uwsgi-plugin-python uwsgi-plugin-sqlite3 supervisor \
  python python-dev python-pip python-setuptools nginx && \
  pip install -r /tmp/requirements.txt && \
  rm /etc/nginx/sites-enabled/default && \
  mkdir /kubyk && \
  apt-get clean

COPY ./app /kubyk/app

COPY ./sqlite /kubyk/sqlite

COPY ./kubyk.py config.py /kubyk/

COPY supervisord.conf /etc/supervisord.conf

COPY uwsgi.ini /etc/uwsgi/

COPY kubyk-nginx.conf /etc/nginx/conf.d/

EXPOSE 80

CMD ["/usr/bin/supervisord"]
