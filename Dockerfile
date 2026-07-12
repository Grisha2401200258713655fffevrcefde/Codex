FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client iputils-ping ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 lynx

WORKDIR /app
COPY --chown=lynx:lynx lynxbrain /app/lynxbrain
COPY --chown=lynx:lynx config /app/config
RUN mkdir -p /app/data /home/lynx/.ssh \
    && chown -R lynx:lynx /app/data /home/lynx/.ssh

USER lynx
ENV PYTHONUNBUFFERED=1
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8088/health', timeout=3)"
CMD ["python", "-m", "lynxbrain"]
