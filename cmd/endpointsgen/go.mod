module stresstestv2

go 1.13

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/google/nftables v0.0.0-20200114154937-bf895afbc6b3
	github.com/sbezverk/nfproxy v0.0.0-20200116155541-f545c2592447
	github.com/sbezverk/nfproxy/pkg/endpointsgen v0.0.0-00010101000000-000000000000
	github.com/sbezverk/nftableslib v0.0.0-20200114155746-9e7edb5c7434
	golang.org/x/sys v0.0.0-20191220220014-0732a990476f
	k8s.io/api v0.17.1
	k8s.io/apimachinery v0.17.1
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/component-base v0.17.0
	k8s.io/klog v1.0.0
	k8s.io/kubernetes v1.17.0
	k8s.io/utils v0.0.0-20200117235808-5f6fbceb4c31
)

replace (
	github.com/sbezverk/nfproxy/pkg/endpointsgen => ../../pkg/endpointsgen
	golang.org/x/sys => golang.org/x/sys v0.0.0-20190813064441-fde4db37ae7a // pinned to release-branch.go1.13
	golang.org/x/tools => golang.org/x/tools v0.0.0-20190821162956-65e3620a7ae7 // pinned to release-branch.go1.13

	// Dependencies that kubernetes specifies them as v0.0.0 which confuses go.mod
	// k8s.io/api => k8s.io/api kubernetes-1.17.0
	// k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver kubernetes-1.17.0
	// k8s.io/apimachinery => k8s.io/apimachinery  kubernetes-1.17.0
	// k8s.io/apiserver => k8s.io/apiserver kubernetes-1.17.0
	// k8s.io/cli-runtime => k8s.io/cli-runtime kubernetes-1.17.0
	// k8s.io/client-go => k8s.io/client-go kubernetes-1.17.0
	// k8s.io/cloud-provider => k8s.io/cloud-provider kubernetes-1.17.0
	// k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap kubernetes-1.17.0
	// k8s.io/code-generator => k8s.io/code-generator kubernetes-1.17.0
	// k8s.io/component-base => k8s.io/component-base kubernetes-1.17.0
	// k8s.io/cri-api => k8s.io/cri-api kubernetes-1.17.0
	// k8s.io/csi-translation-lib => k8s.io/csi-translation-lib kubernetes-1.17.0
	// k8s.io/kube-aggregator => k8s.io/kube-aggregator kubernetes-1.17.0
	// k8s.io/kube-controller-manager => k8s.io/kube-controller-manager kubernetes-1.17.0
	// k8s.io/kube-proxy => k8s.io/kube-proxy kubernetes-1.17.0
	// k8s.io/kube-scheduler => k8s.io/kube-scheduler kubernetes-1.17.0
	// k8s.io/kubectl => k8s.io/kubectl kubernetes-1.17.0
	// k8s.io/kubelet => k8s.io/kubelet kubernetes-1.17.0
	// k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers kubernetes-1.17.0
	// k8s.io/metrics => k8s.io/metrics kubernetes-1.17.0
	// k8s.io/sample-apiserver => k8s.io/sample-apiserver kubernetes-1.17.0

	k8s.io/api => k8s.io/api v0.17.0
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.17.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.17.1-beta.0
	k8s.io/apiserver => k8s.io/apiserver v0.17.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.17.0
	k8s.io/client-go => k8s.io/client-go v0.17.0
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.17.0
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.17.0
	k8s.io/code-generator => k8s.io/code-generator v0.17.1-beta.0
	k8s.io/component-base => k8s.io/component-base v0.17.0
	k8s.io/cri-api => k8s.io/cri-api v0.17.1-beta.0
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.17.0
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.17.0
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.17.0
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.17.0
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.17.0
	k8s.io/kubectl => k8s.io/kubectl v0.17.0
	k8s.io/kubelet => k8s.io/kubelet v0.17.0
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.17.0
	k8s.io/metrics => k8s.io/metrics v0.17.0
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.17.0
)
