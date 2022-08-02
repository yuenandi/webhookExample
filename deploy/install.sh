#!/bin/bash

ns='webhook-example'
kubectl_ns='--namespace webhook-example'
#kube_config='--kubeconfig config'



sed -e "s/\${namespace}/${ns}/g" rbac.yaml > current_rbac.yaml
kubectl apply -f current_rbac.yaml  ${kubectl_ns} ${kube_config}

./webhook-create-signed-cert.sh  ${kubectl_ns} ${kube_config}

kubectl apply -f service.yaml

kubectl apply -f webhook-example.yaml

cat ./mutatingwebhook.yaml | ./webhook-patch-ca-bundle.sh > current_mutatingwebhook.yaml ${kube_config} && kubectl apply -f current_mutatingwebhook.yaml ${kubectl_ns}



kubectl label ns ${ns} webhook-example=enabled ${kube_config}