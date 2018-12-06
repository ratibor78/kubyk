FROM debian:stretch-slim
MAINTAINER Alexey Nizhegolenko <ratibor78@gmail.com>

RUN mkdir /opt/kubyk
COPY . /opt/kubyk

RUN \
  apt-get update && \
  apt-get install -y --no-install-recommends uwsgi uwsgi-plugin-python uwsgi-plugin-sqlite3 python python-dev python-pip python-setuptools && \
  apt-get clean && \
  pip install -r /opt/kubyk/requirements.txt


EXPOSE 8080

CMD uwsgi --ini /opt/kubyk/uwsgi.ini
