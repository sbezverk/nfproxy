
[![Build Status](https://travis-ci.org/sbezverk/nfproxy.svg?branch=master)](https://travis-ci.org/sbezverk/nfproxy)

<p align="left">
  <img src="https://github.com/sbezverk/nfproxy/blob/master/Logo_final.png?raw=true" width="40%" height="40%">
</p>

## kubernetes proxy functionality based on nftables

## Goal

The goal of nfproxy is to provide high performance and scalable kubernetes proxy supporting both ipv4 and ipv6. 
**nfproxy** is not a 1:1 copy of kube-proxy (iptables) in terms of features. **nfproxy** is not going to cover all corner
cases and special features addressed by kube-proxy if these features compromise the design principle of nfproxy which is

**"There is no rules per service or per endpoint"**. 

Meaning that the number of rules in one chain will not correlate to a number of services or endpoints.

This principle will limit applications of nfproxy, but on the other hand for the cases where nfproxy
can be used, it will offer superior performance and scalability when comparing with kube-proxy (iptables) implementation.

## Build

To build nfproxy binary execute:

```
make nfproxy
```
Resulting binary will be placed in *./bin* folder.

To build a container:

```
make container IMAGE_VERSION=X.X.X REGISTRY_NAME=docker.io/somename
```
This command will compile nfproxy binary and then will build a docker container tagged with
**REGISTRY_NAME/nfproxy:IMAGE_VERSION** and placed it in a local docker image store.

## Deployment

`Nfproxy` can be deployed in two ways;

* Replace the Kubernetes `kube-proxy`. All services will be served by `nfproxy`

* Install `nfproxy` and select which services that shall be served by `nfproxy` using the label `service.kubernetes.io/service-proxy-name: nfproxy`. The K8s installation (kube-proxy) is not altered.



### Replace kube-proxy


1. Find a way to save kube-proxy's daemonset yaml, once you tired of playing with nfproxy,
this yaml will allow you to restore the default kube-proxy functionality.

2. Delete kube-proxy daemonset and clean up iptables entries if kube-proxy ran in iptables mode

```
kubectl delete daemonset -n kube-system kube-proxy

sudo iptables -F -t nat

sudo iptables -F -t filter
```

3. Modify nfproxy deployment yaml file to specify your cluster's CIDR and location of nfproxy image if not default
is used. 
**nfproxy** deployment file is located at ./deployment/nfproxy.yaml.

Change:
```
- "57.112.0.0/12"
```

For your cluster's cidr range.
```
- "X.Y.Z.0/L"
```
Where *L* is length in bits of your cluster's cidr.

Specify Api server public endpoint for **API_PUBLIC_ENDPOINT** variable, for example:
```
- name: API_PUBLIC_ENDPOINT
  value: "https://192.168.80.221:6443"
```

To use EndpointSlice controller instead of Endpoints controller add:
```
- --endpointslice
- "true"
```

4. Deploy nfproxy

```
kubectl create -f ./deployment/nfproxy.yaml
```

5. Check nfproxy pod's log

```
kubectl logs -n kube-system nfproxy-blah
```
If nfproxy started successfully, pod's log will contain messages about discovered services.

6. To delete nfproxy

```
kubectl delete -f ./deployment/nfproxy.yaml
```

### Select nfproxy with a label

`Nfproxy` is installed as any application and will only be used for services that explicitly request it. Example;

```
apiVersion: v1
kind: Service
metadata:
  name: my-service
  labels:
    service.kubernetes.io/service-proxy-name: nfproxy
spec:
  ipFamily: IPv4
  selector:
    app: some-http-server
  ports:
  - port: 80
  type: LoadBalancer
```

The `service.kubernetes.io/service-proxy-name` will make the `kube-proxy` ignore the service. Instead `nfproxy` watches services with this label an will setup nftables for load balancing.

Deployment follows the same steps as when `kube-proxy` is replaced minus the removal of `kube-proxy` (obviously). Perform the steps from **3** above but use `./deployment/nfproxy-label-select.yaml` instead.



## Status

**nfproxy** testing is done by running SIG-Network E2E tests in a 2 and 5 nodes clusters. 
The command line to run tests is the following:
```
 ./bazel-bin/test/e2e/e2e.test  -ginkgo.focus="\[sig-network\].*Service" -kubeconfig={location of kubeconfig file} -dns-domain={cluster's domain name}
```
Below is the summary of results:

**2 and 5 nodes clusters, Calico CNI, Endpoints Controller**

Summarizing 2 Failures:
```
[Fail] [sig-network] EndpointSlice [Feature:EndpointSlice] version v1 [It] should create Endpoints and EndpointSlices for Pods matching a Service 
test/e2e/network/endpointslice.go:216

[Fail] [sig-network] Services [It] should handle load balancer cleanup finalizer for service [Slow] 
test/e2e/framework/service/wait.go:79

Ran 28 of 4845 Specs in 2138.719 seconds
FAIL! -- 26 Passed | 2 Failed | 0 Pending | 4817 Skipped
```

First failure is related to EndpointSlice controller being not enabled. 
Second failure is not **nfproxy** related as it fails the same way in cases where nfproxy is not used. 

**2 and 5 nodes clusters, Calico CNI, EndpointSlice Controller**

```
Summarizing 1 Failure:

[Fail] [sig-network] Services [It] should handle load balancer cleanup finalizer for service [Slow] 
test/e2e/framework/service/wait.go:79

Ran 28 of 4845 Specs in 2042.535 seconds
FAIL! -- 27 Passed | 1 Failed | 0 Pending | 4817 Skipped
--- FAIL: TestE2E (2042.55s)
FAIL
```
Failure is not **nfproxy** related as it fails the same way in cases where nfproxy is not used. 

**Contributors, reviewers, testers are welcome!!!**
