FROM zeek/zeek:latest

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app



CMD ["/bin/bash"]