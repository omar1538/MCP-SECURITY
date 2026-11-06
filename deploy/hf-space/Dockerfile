# Hugging Face Space (Docker SDK) for the MCP Security Gateway live demo.
# The Space repo only needs this Dockerfile and README.md; the code is pulled
# from GitHub at build time. The demo runs in scripted mode (no LLM required).

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MSG_DATA_DIR=/tmp/msgdata \
    GIT_REF=main

RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN git clone --depth 1 --branch "${GIT_REF}" \
      https://github.com/omar1538/MCP-SECURITY.git /app \
 && pip install -e "."

# runtime data is written to a world-writable dir so the Space works whether it
# runs as root or as an unprivileged user.
RUN mkdir -p /tmp/msgdata && chmod 0777 /tmp/msgdata

EXPOSE 7860

# generate the synthetic world fresh on boot, then serve on the HF port
CMD mkdir -p "$MSG_DATA_DIR" \
 && python -m data.generate --seed 7 --out "$MSG_DATA_DIR" \
 && uvicorn server.app:app --host 0.0.0.0 --port 7860
