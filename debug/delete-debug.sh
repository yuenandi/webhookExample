#!/bin/bash


ns=webhook-example
kubectl_ns='-n webhook-example'
#kube_config='--kubeconfig config'




kubectl delete  secret/webhook-example-debug ${kubectl_ns} ${kube_config}

kubectl delete  mutatingwebhookconfiguration.admissionregistration.k8s.io/webhook-example-debug  ${kubectl_ns} ${kube_config}

kubectl label ns ${ns} webhook-example-debug- ${kube_config}