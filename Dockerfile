FROM telegraf:1.39

USER root

RUN apt-get update && \
    apt-get install -y snmp && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER telegraf
