[![Build Status](https://travis-ci.org/sbezverk/nfproxy.svg?branch=master)](https://travis-ci.org/sbezverk/nfproxy)
# **nfproxy**
## kubernetes proxy functionality based on nftables

## Goal

The goal of nfproxy is to provide high performance and scalable kubernetes proxy supporting both ipv4 and ipv6. 
**nfproxy** is not a 1:1 copy of kube-proxy (iptables) in terms of features. **nfproxy** is not going to cover all corner
cases and special features addressed by kube-proxy if these features compromise the design principle of nfproxy which is

**"There is no rules per service or per endpoint"**. 

Meaning that the number of rules in one chain will not correlate to a number of services or endpoints.

This principle will limit applications of nfproxy, but on the other hand for the cases where nfproxy
can be used, it will offer superior performance and scalability when comparing with kube-proxy (iptables) implementation.

**NOTE:** It is WIP, please expect rather high volume of changes.

**Contributors, reviewers, testers are welcome!!!**
