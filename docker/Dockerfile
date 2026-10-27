FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MSG_DATA_DIR=/data

WORKDIR /app
COPY pyproject.toml README.md ./
COPY agent ./agent
COPY mcp_servers ./mcp_servers
COPY gateway ./gateway
COPY attacks ./attacks
COPY data ./data
COPY eval ./eval

RUN pip install -e "." && mkdir -p /data

# non-root
RUN useradd -m app && chown -R app /app /data
USER app

EXPOSE 8101 8102 8103 8104
CMD ["python", "-m", "mcp_servers.transactions", "--host", "0.0.0.0", "--port", "8102"]
