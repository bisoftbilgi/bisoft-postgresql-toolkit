FROM docker.elastic.co/logstash/logstash:8.15.0

USER root

# System Tools + PostgreSQL client + JDBC plugin install
RUN apt-get update && \
    apt-get install -y wget curl postgresql-client iproute2 && \
    rm -rf /var/lib/apt/lists/* && \
    /usr/share/logstash/bin/logstash-plugin install --no-verify logstash-output-jdbc

# Correct directory for the JDBC driver
RUN mkdir -p /usr/share/logstash/vendor/jar/jdbc/

# Installation PostgreSQL JDBC driver 
RUN wget -q https://jdbc.postgresql.org/download/postgresql-42.7.8.jar \
    -O /usr/share/logstash/vendor/jar/jdbc/postgresql.jar

# Correct permissions for the Logstash user
RUN chown -R logstash:logstash /usr/share/logstash/vendor/jar/jdbc/

USER logstash
