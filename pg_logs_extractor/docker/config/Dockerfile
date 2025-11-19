# Logstash 8.15 base image
FROM docker.elastic.co/logstash/logstash:8.15.0

USER root

# System tools, PostgreSQL client, plugin ve JDBC driver
RUN apt-get update && \
    apt-get install -y wget curl postgresql-client iproute2 && \
    rm -rf /var/lib/apt/lists/* && \
    /usr/share/logstash/bin/logstash-plugin install --no-verify logstash-output-jdbc && \
    mkdir -p /usr/share/logstash/logstash-core/lib/jars/ && \
    wget -q https://jdbc.postgresql.org/download/postgresql-42.7.8.jar -O /usr/share/logstash/logstash-core/lib/jars/postgresql-42.7.8.jar

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
