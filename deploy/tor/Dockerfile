FROM --platform=linux/amd64 debian:bookworm-slim@sha256:311f7a192fd9a92b165a86b32fa3aae9005b11849bfb1db2d4fd784559ee464f

RUN apt-get update \
    && apt-get install --yes --no-install-recommends tor \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/tor/ustoy-hidden \
    && chown -R debian-tor:debian-tor /var/lib/tor \
    && chmod 0700 /var/lib/tor/ustoy-hidden

COPY torrc /etc/tor/torrc
USER debian-tor:debian-tor
EXPOSE 9050
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
