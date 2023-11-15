FROM python:3.11-slim

# Prevent writing __pycache__ in /sls/MX/applications/mxlibs3/all-beamlines/stable"
# Set the PATH and PYTHONPATH to include mounted gunicorn app, mxlibs3 and mxdbclient.
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/conda/bin:$PATH \
    PYTHONPATH="${PYTHONPATH}:/sls/MX/applications/mxlibs3/all-beamlines/stable:/sls/MX/applications/mxdbclient/all-beamlines/stable"

RUN apt-get update --fix-missing && \
    apt-get install -y vim libsasl2-dev python-dev-is-python3 libldap2-dev libssl-dev gcc && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get purge -y vim && apt-get autoremove -y 

COPY logging.conf /root

# Prepare directory for gunicorn app, mxlibs3 and mxdbclient. They will be mounted in docker-compose
RUN mkdir /opt/app && \
    mkdir -p /sls/MX/applications/mxlibs3/all-beamlines/stable && \
    mkdir -p /sls/MX/applications/mxdbclient/all-beamlines/stable

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

WORKDIR /opt/app

# expose the port 8000
EXPOSE 8000

# https://stackoverflow.com/questions/25319690/how-do-i-run-a-flask-app-in-gunicorn-if-i-used-the-application-factory-pattern
CMD ["gunicorn", "--bind", ":8000",  "--log-config", "/root/logging.conf", "--worker-class", "gevent", "--worker-connections", "1000 ", "--workers", "1",  "server:create_app()"]