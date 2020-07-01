FROM registry.access.redhat.com/ubi8:latest

USER 0

COPY . /tmp/src

RUN rm -rf /tmp/src/.git* && \
    chown -R 1001 /tmp/src && \
    chgrp -R 0 /tmp/src && \
    chmod -R g+w /tmp/src && \
    cp -rp /tmp/src/.s2i/bin /tmp/scripts

USER 1001

RUN /tmp/scripts/assemble

CMD ["/usr/libexec/s2i/run"]
