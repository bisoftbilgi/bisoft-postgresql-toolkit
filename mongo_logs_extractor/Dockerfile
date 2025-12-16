FROM docker.elastic.co/logstash/logstash:8.19.7

USER root

RUN apt-get update && \
    apt-get install -y wget curl postgresql-client iproute2 && \
    rm -rf /var/lib/apt/lists/* && \
    /usr/share/logstash/bin/logstash-plugin install --no-verify logstash-output-jdbc && \
    /usr/share/logstash/bin/logstash-plugin install logstash-filter-throttle && \
    mkdir -p /usr/share/logstash/logstash-core/lib/jars/ && \
    wget -q https://jdbc.postgresql.org/download/postgresql-42.7.8.jar -O /usr/share/logstash/logstash-core/lib/jars/postgresql-42.7.8.jar
USER logstash
