#!/bin/sh

#
# Switching default FORWARD chain policy Drop to Accept
# required in a multinode kubernetes cluster environment
#
echo "Switching filter's FORWARD chain policy to ACCEPT.."

/sbin/iptables -t filter -P FORWARD ACCEPT || true

exit 0
