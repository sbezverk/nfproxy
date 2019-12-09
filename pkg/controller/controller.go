package controller

import "k8s.io/client-go/kubernetes"

// Controller exposes methods for Services and Endpoints controllers
type Controller interface{}

type controller struct {
	clientset *kubernetes.Clientset
}

// NewController return a new instance of Services and Endpoints controller
func NewController(clientset *kubernetes.Clientset) Controller {
	return controller{clientset: clientset}
}
