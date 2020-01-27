## Services and Endpoints generator

endpointsgen is a tool to generate a specified number of services and corresponding endpoints. It is used for nfproxy
functionality and stress testing.

## To Run

In order to run it, cluster's client kubeconfig file with sufficient privileges must be provided in **--kubeconfig** parameter. 
Other parameters include:

	--kubeconfig      - Absolute path to the kubeconfig file.
	--stack-mode      - Defines which stack is tested, acceptable values are: ipv4, ipv6, dual. Note: Dual stack is not yet supported.
	--svc             - Number of services to generate.
	--subset          - Number of Subsets in a single endpoint.
	--ip              - Number of addresses in an endpoint subset.
	--start-ipv4      - Starting ipv4 for endpoint's subset's addrersses. Default: 1.0.0.0
	--start-ipv6      - Starting ipv6 for endpoint's subset's addrersses. Defaut: 2001:1::0
	--namespace       - Namespace where services and endpoints are generated. Default: endpoints-test
	--initial-cleanup - Clean up all service and endpoints from the namespace prior attempting to create them. Default: true
	--post-cleanup    - Clean up all service and endpoints from the namespace after running tests. Default: false
	--max-etcd        - ETCD is configured for max size of backend strage. Default: false
    --just-cleanup    - Clean up all service and endpoints from the namespace and exit. Default: false

Example to create 10 services and 10 endpoints and each endpoint with 2 subsets and each subset with 2 IP addresses, the command would look like:

```
endpointsgen --kubeconfig={path to kubeconfig file} --svc=10 --subset=2 --ip=2

```
The resulting services objects will look like:

```
kubectl get svc -n endpoints-test
NAME                TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)                                   AGE
app-32da761d-da26   ClusterIP   57.136.203.220   <none>        16416/TCP,16417/TCP,16418/TCP,16419/TCP   22s
app-552d83be-1a32   ClusterIP   57.129.232.171   <none>        16420/TCP,16421/TCP,16422/TCP,16423/TCP   21s
app-64b2494a-4d9a   ClusterIP   57.143.211.71    <none>        16392/TCP,16393/TCP,16394/TCP,16395/TCP   28s
app-6bb9f389-1967   ClusterIP   57.134.111.208   <none>        16396/TCP,16397/TCP,16398/TCP,16399/TCP   27s
app-8917ea7f-f620   ClusterIP   57.141.247.55    <none>        16408/TCP,16409/TCP,16410/TCP,16411/TCP   24s
app-8b27155e-0bbd   ClusterIP   57.143.170.242   <none>        16400/TCP,16401/TCP,16402/TCP,16403/TCP   26s
app-97f73589-84cd   ClusterIP   57.143.10.180    <none>        16404/TCP,16405/TCP,16406/TCP,16407/TCP   25s
app-98458437-f3f7   ClusterIP   57.129.1.17      <none>        16384/TCP,16385/TCP,16386/TCP,16387/TCP   30s
app-b6e0d9d2-a379   ClusterIP   57.134.48.177    <none>        16412/TCP,16413/TCP,16414/TCP,16415/TCP   23s
app-bbd54823-2c99   ClusterIP   57.137.50.91     <none>        16388/TCP,16389/TCP,16390/TCP,16391/TCP   29s
```

The resulting endpoints objects will look like:

```
app-32da761d-da26   1.0.0.33:16416,1.0.0.34:16416,1.0.0.33:16417 + 5 more...   66s
app-552d83be-1a32   1.0.0.37:16421,1.0.0.38:16421,1.0.0.37:16420 + 5 more...   66s
app-64b2494a-4d9a   1.0.0.11:16395,1.0.0.12:16395,1.0.0.11:16394 + 5 more...   66s
app-6bb9f389-1967   1.0.0.13:16396,1.0.0.14:16396,1.0.0.13:16397 + 5 more...   66s
app-8917ea7f-f620   1.0.0.25:16408,1.0.0.26:16408,1.0.0.25:16409 + 5 more...   66s
app-8b27155e-0bbd   1.0.0.17:16400,1.0.0.18:16400,1.0.0.17:16401 + 5 more...   66s
app-97f73589-84cd   1.0.0.21:16405,1.0.0.22:16405,1.0.0.21:16404 + 5 more...   66s
app-98458437-f3f7   1.0.0.1:16385,1.0.0.2:16385,1.0.0.1:16384 + 5 more...      66s
app-b6e0d9d2-a379   1.0.0.31:16415,1.0.0.32:16415,1.0.0.31:16414 + 5 more...   66s
app-bbd54823-2c99   1.0.0.5:16389,1.0.0.6:16389,1.0.0.5:16388 + 5 more...      66s
```

One of generated service object:

```
apiVersion: v1
kind: Service
metadata:
  labels:
    endpoints/stressTest: "true"
  name: app-32da761d-da26
  namespace: endpoints-test
spec:
  clusterIP: 57.136.203.220
  ports:
  - name: 1-0-0-33
    port: 16416
    protocol: TCP
    targetPort: 16416
  - name: 1-0-0-34
    port: 16417
    protocol: TCP
    targetPort: 16417
  - name: 1-0-0-35
    port: 16418
    protocol: TCP
    targetPort: 16418
  - name: 1-0-0-36
    port: 16419
    protocol: TCP
    targetPort: 16419
  sessionAffinity: None
  type: ClusterIP
status:
  loadBalancer: {}
```

One of generated endpoints object:

```
apiVersion: v1
kind: Endpoints
metadata:
  labels:
    endpoints/stressTest: "true"
  name: app-32da761d-da26
  namespace: endpoints-test
subsets:
- addresses:
  - hostname: host-1-0-0-33
    ip: 1.0.0.33
  - hostname: host-1-0-0-34
    ip: 1.0.0.34
  ports:
  - name: 1-0-0-33
    port: 16416
    protocol: TCP
  - name: 1-0-0-34
    port: 16417
    protocol: TCP
- addresses:
  - hostname: host-1-0-0-35
    ip: 1.0.0.35
  - hostname: host-1-0-0-36
    ip: 1.0.0.36
  ports:
  - name: 1-0-0-35
    port: 16418
    protocol: TCP
  - name: 1-0-0-36
    port: 16419
    protocol: TCP
```