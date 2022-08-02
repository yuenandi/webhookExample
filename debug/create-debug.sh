#!/bin/bash

currentIp=10.8.1.90
currentPort=6444
ns='webhook-example'
kubectl_ns='--namespace webhook-example'
#kube_config='--kubeconfig config'


./webhook-create-signed-cert.sh  ${kubectl_ns} ${kube_config} --current-ip ${currentIp}

sed -e "s|\${URL}|https:\/\/${currentIp}:${currentPort}\/mutate\/|g" mutatingwebhook.yaml | ./webhook-patch-ca-bundle.sh ${kube_config} > current_mutatingwebhook.yaml  && kubectl apply -f current_mutatingwebhook.yaml ${kubectl_ns} ${kube_config}

kubectl label ns ${ns} webhook-example-debug=enabled ${kube_config}