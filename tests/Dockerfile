# Kernel-level test image: small Alpine with real ipset/iptables.
#
# The applier needs NET_ADMIN and its own network namespace, so the container
# must run with --privileged (or --cap-add NET_ADMIN --cap-add NET_RAW).
FROM alpine:3.20

RUN apk add --no-cache bash ipset iptables util-linux \
    && mkdir -p /run/lock

WORKDIR /opt/ip_list_aggregator
CMD ["/bin/bash"]
