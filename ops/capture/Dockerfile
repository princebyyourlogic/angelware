FROM python:3.12-slim
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=UTC
RUN apt-get update \
    && apt-get install -y --no-install-recommends wireshark-common \
    && rm -rf /var/lib/apt/lists/* \
    && chmod u-s /usr/bin/dumpcap
COPY capture.py /app/capture.py
ENTRYPOINT ["python", "/app/capture.py"]
