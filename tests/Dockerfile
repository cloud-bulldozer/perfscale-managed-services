FROM quay.io/redhat-aqe/tox:latest
RUN useradd -m -U fedora
USER fedora
COPY --chown=fedora:fedora ../. /home/fedora
WORKDIR /home/fedora
CMD ["tox", "."]
