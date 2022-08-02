#!/bin/bash

ns=webhook-example
kubectl_ns='-n webhook-example'
#kube_config='--kubeconfig config'

kubectl delete serviceaccount/webhook-example-sa  ${kubectl_ns} ${kube_config}

kubectl delete clusterrole.rbac.authorization.k8s.io/webhook-example-cr  ${kubectl_ns} ${kube_config}

kubectl delete clusterrolebinding.rbac.authorization.k8s.io/webhook-example-crb   ${kubectl_ns} ${kube_config}

kubectl delete  secret/webhook-example ${kubectl_ns} ${kube_config}

kubectl delete service/webhook-example  ${kubectl_ns} ${kube_config}

kubectl delete deployment.apps/webhook-example   ${kubectl_ns} ${kube_config}

kubectl delete  configmap/webhook-example  ${kubectl_ns} ${kube_config}

kubectl delete  mutatingwebhookconfiguration.admissionregistration.k8s.io/webhook-example  ${kubectl_ns} ${kube_config}


kubectl label ns ${ns} webhook-example- ${kube_config}