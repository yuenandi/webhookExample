package k8s

import (
	"context"
	"crypto/x509"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/webhookExample/options"
	"io/ioutil"
	admissionV1 "k8s.io/api/admissionregistration/v1"
	certificatesV1beta1 "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
	"sigs.k8s.io/yaml"
	"time"
)

const (
	inClusterCAFilePath              = "/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	mutatingWebhookName              = "webhook-example.github.com"
	mutationWebhookConfigurationName = "webhook-example"
)

var webhookLabel = map[string]string{"app": mutationWebhookConfigurationName}

type K8s struct {
	kubernetesClient *kubernetes.Clientset
	config           *rest.Config
	parameters       *options.WhSvrParameters
}

func NewK8s(options *options.WhSvrParameters) *K8s {
	k, err := NewKubernetsClient(options)
	if err != nil {
		logrus.Panic(err)
	}
	k.parameters = options
	return k
}

func (k *K8s) Run() (err error) {

	csr, key, err := genKubernetesCSR()
	if err != nil {
		return err
	}
	csr, err = k.kubernetesClient.CertificatesV1beta1().CertificateSigningRequests().Create(context.Background(), csr, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	logrus.Infof("Create CSR %s  success", csr.Name)
	cert, err := k.Approve(csr)
	if err != nil {
		return err
	}
	keyBuf := x509.MarshalPKCS1PrivateKey(key)
	if err != nil {
		return err
	}

	err = writePki(k.parameters.KeyFile, "RSA PRIVATE KEY", keyBuf)
	if err != nil {
		return err
	}
	err = writeCert(k.parameters.CertFile, cert)
	if err != nil {
		return err
	}
	err = k.kubernetesClient.CertificatesV1beta1().CertificateSigningRequests().Delete(context.Background(), csr.Name, metav1.DeleteOptions{})
	if err != nil {
		logrus.Warnf("Remove CSR %s is failure", csr.Name)
	}
	var (
		path    = options.MutatePath
		url     string
		service *admissionV1.ServiceReference
	)
	logrus.Debugf("DEBUG模式：%t", k.parameters.IsDebug)
	if k.parameters.IsDebug {
		url = fmt.Sprintf("https://%s:%d%s", k.parameters.Url, k.parameters.Port, path)
		err = k.CreateMutationWebhook(mutationWebhookConfigurationName, mutatingWebhookName, nil, &url)
	} else {
		service = &admissionV1.ServiceReference{
			Name:      k.parameters.Service,
			Namespace: k.parameters.Namespace,
			Path:      &path,
		}
		logMU, _ := yaml.Marshal(service)
		logrus.Debugf(string(logMU))
		err = k.CreateMutationWebhook(mutationWebhookConfigurationName, mutatingWebhookName, service, nil)
	}

	return err

}

func (k *K8s) CreateMutationWebhook(mutatingWebhookConfiguration, webhookName string, service *admissionV1.ServiceReference, url *string) error {
	var (
		ca  []byte
		err error
	)
	if len(k.config.CAData) > 0 {
		ca = k.config.CAData
	} else {
		ca, err = ioutil.ReadFile(inClusterCAFilePath)
		if err != nil {
			logrus.Panic(err)
			return err
		}
	}

	sec := admissionV1.SideEffectClass(admissionV1.SideEffectClassNone)
	mutationWebhook := &admissionV1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:   mutatingWebhookConfiguration,
			Labels: webhookLabel,
		},
		Webhooks: []admissionV1.MutatingWebhook{
			admissionV1.MutatingWebhook{
				Name: webhookName,
				ClientConfig: admissionV1.WebhookClientConfig{
					Service:  service,
					URL:      url,
					CABundle: ca,
				},
				AdmissionReviewVersions: []string{"v1beta1"},
				SideEffects:             &sec,
				Rules: []admissionV1.RuleWithOperations{
					admissionV1.RuleWithOperations{
						Operations: []admissionV1.OperationType{
							admissionV1.Create,
						},
						Rule: admissionV1.Rule{
							APIGroups:   []string{"apps"},
							APIVersions: []string{"v1"},
							Resources:   []string{"deployments"},
						},
					},
				},
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"webhook-example": "enabled"},
				},
			},
		},
	}

	_, err = k.kubernetesClient.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(context.Background(), mutationWebhook, metav1.CreateOptions{})
	if err != nil {
		if errors.IsAlreadyExists(err) {
			logrus.Warnf("MutatingWebhookConfigurations %s is already exist", mutatingWebhookConfiguration)
		} else {
			return err
		}
	} else {
		logrus.Infof("Create MutatingWebhookConfigurations %s success", mutatingWebhookConfiguration)
	}
	return nil
}

func (k *K8s) Approve(csr *certificatesV1beta1.CertificateSigningRequest) ([]byte, error) {
	// is approved
	if len(csr.Status.Certificate) > 0 {
		return nil, nil
	}
	csr.Status = certificatesV1beta1.CertificateSigningRequestStatus{
		Conditions: []certificatesV1beta1.CertificateSigningRequestCondition{{
			Type:    "Approved",
			Reason:  "WebhookApprove",
			Message: "This CSR was approved by webhook",
			LastUpdateTime: metav1.Time{
				Time: time.Now(),
			},
		}},
	}

	// approve csr
	csr, err := k.kubernetesClient.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(context.Background(), csr, metav1.UpdateOptions{})

	if err != nil {
		klog.Errorln(err)
		return nil, err
	}
	for {
		approveCsr, err := k.kubernetesClient.CertificatesV1beta1().CertificateSigningRequests().Get(context.Background(), csr.Name, metav1.GetOptions{})
		if err != nil {
			klog.Errorln(err)
			return nil, err
		}
		if approveCsr.Status.Certificate != nil {
			logrus.Infof("Approve CSR %s  success", csr.Name)
			return approveCsr.Status.Certificate, nil
		}
		time.Sleep(time.Second * 5)
	}
	return nil, nil
}
