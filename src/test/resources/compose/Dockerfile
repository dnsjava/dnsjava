# inspired by https://github.com/adegtyarev/docker-dante
FROM    alpine:3.20

ARG     SOCKD_USER_NAME
ARG     SOCKD_USER_PASSWORD

ENV     SOCKD_USER_NAME ${SOCKD_USER_NAME}
ENV     SOCKD_USER_PASSWORD ${SOCKD_USER_PASSWORD}

ENV     DANTE_VER 1.4.2
ENV     DANTE_URL https://www.inet.no/dante/files/dante-$DANTE_VER.tar.gz
ENV     DANTE_SHA 4c97cff23e5c9b00ca1ec8a95ab22972813921d7fbf60fc453e3e06382fc38a7

RUN     apk add --no-cache --virtual .build-deps \
            build-base \
            curl \
            bind-tools \
            linux-pam-dev && \
        install -v -d /src && \
        curl -sSL $DANTE_URL -o /src/dante.tar.gz && \
        echo "$DANTE_SHA */src/dante.tar.gz" | sha256sum -c && \
        tar -C /src -vxzf /src/dante.tar.gz && \
        cd /src/dante-$DANTE_VER && \
        # https://lists.alpinelinux.org/alpine-devel/3932.html
        ac_cv_func_sched_setscheduler=no ./configure --build=aarch64-unknown-linux-gnu && \
        make -j install && \
        cd / && rm -r /src && \
        apk del .build-deps && \
        apk add --no-cache \
            curl \
            linux-pam

COPY    sockd.conf /etc/
COPY    entrypoint.sh /

EXPOSE  1080

ENTRYPOINT ["/entrypoint.sh"]
CMD     ["sockd"]
