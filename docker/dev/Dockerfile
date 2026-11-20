ARG BASE_IMAGE=nginxproxymanager/nginx-full:certbot-node@sha256:160438ca30f5d290dcc878f9fe32ecb142739a477bd6a508b852cc5a31f22dec
FROM $BASE_IMAGE AS nginx-builder
COPY scripts/build-nginx-security /tmp/build-nginx-security
COPY patches/nginx-1.31.9.patch /tmp/nginx-1.31.9.patch
RUN bash /tmp/build-nginx-security

FROM nginxproxymanager/testca AS testca
FROM $BASE_IMAGE
COPY --from=nginx-builder /out/sbin/nginx /usr/sbin/nginx
COPY --from=nginx-builder /out/modules/ /usr/lib/nginx/modules/
LABEL maintainer="Jamie Curnow <jc@jc21.com>"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV SUPPRESS_NO_CONFIG_WARNING=1 \
	S6_BEHAVIOUR_IF_STAGE2_FAILS=1 \
	S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0 \
	S6_FIX_ATTRS_HIDDEN=1 \
	S6_KILL_FINISH_MAXTIME=10000 \
	S6_VERBOSITY=2 \
	NODE_OPTIONS="--openssl-legacy-provider"

RUN echo "fs.file-max = 65535" > /etc/sysctl.conf \
	&& apt-get update \
	&& apt-get install -y jq python3-pip logrotate moreutils \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# Task
WORKDIR /usr
RUN curl -sL 'https://taskfile.dev/install.sh' | sh

COPY rootfs /

COPY scripts/install-s6 /tmp/install-s6
RUN rm -f /etc/nginx/conf.d/production.conf.template \
	&& chmod 644 /etc/logrotate.d/nginx-proxy-manager \
	&& /tmp/install-s6 "${TARGETPLATFORM}" \
	&& rm -f /tmp/install-s6 \
	&& chmod 644 -R /root/.cache

# Copy test CA cert for use in container and add to trusted certs from a self-signed CA
COPY --from=testca /home/step/certs/root_ca.crt /etc/ssl/certs/NginxProxyManager.crt
WORKDIR /etc/ssl/certs
RUN ln -s NginxProxyManager.crt 1d0e3f10.0 && update-ca-certificates

WORKDIR /root

EXPOSE 80 81 443
ENTRYPOINT [ "/init" ]
