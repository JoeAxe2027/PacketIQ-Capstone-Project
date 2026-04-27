FROM zeek/zeek:latest

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && if [ -f "requirements.txt" ]; then /opt/venv/bin/pip install --no-cache-dir -r requirements.txt; fi

ENV PATH="/opt/venv/bin:$PATH"

CMD uvicorn api:app --host 0.0.0.0 --port ${PORT}
