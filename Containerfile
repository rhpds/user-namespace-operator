FROM quay.io/rhpds/python-kopf-s2i:v1.38

USER 0

COPY . /tmp/src

RUN rm -rf /tmp/src/.git* && \
    chown -R 1001 /tmp/src && \
    chgrp -R 0 /tmp/src && \
    chmod -R g+w /tmp/src

USER 1001

RUN /usr/libexec/s2i/assemble

CMD ["/usr/libexec/s2i/run"]
