package k8s

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/webhookExample/options"
	certificatesV1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	rsaKeySize = 2048
	WEBHOOKCSR = "webhook-example"
)

func NewKubernetsClient(options *options.WhSvrParameters) (k *K8s, err error) {
	k = &K8s{}
	config, err := clientcmd.BuildConfigFromFlags("", options.KubeConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	k.config = config
	k.kubernetesClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return k, nil
}

// GenKubernetesCSR generates a new key and KubernetesCSR
func genKubernetesCSR() (*certificatesV1beta1.CertificateSigningRequest, *rsa.PrivateKey, error) {

	serviceName := options.Parameters.Service
	namespace := options.Parameters.Namespace

	dns := []string{serviceName, fmt.Sprintf("%s.%s", serviceName, namespace), fmt.Sprintf("%s.%s.svc", serviceName, namespace)}
	var ips []net.IP
	ips = append(ips, net.ParseIP(options.Parameters.Url))
	csrConfig := &cert.Config{
		CommonName:   fmt.Sprintf("%s.%s.svc", serviceName, namespace),
		Organization: []string{fmt.Sprintf("%s.%s.svc", serviceName, namespace)},
		AltNames: cert.AltNames{
			DNSNames: dns,
			IPs:      ips,
		},
	}

	x509csr, x509key, err := NewCSRAndKey(csrConfig)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	var csrBuffer bytes.Buffer

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, x509csr, x509key)

	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	err = pem.Encode(&csrBuffer, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	csr := csrBuffer.Bytes()
	csrName := fmt.Sprintf("%s.%s-%d", WEBHOOKCSR, namespace, time.Now().Unix())

	return &certificatesV1beta1.CertificateSigningRequest{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CertificateSigningRequest",
			APIVersion: "certificates.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels: webhookLabel,
			Name:   csrName,
		},
		Spec: certificatesV1beta1.CertificateSigningRequestSpec{
			Request:  csr,
			Usages:   []certificatesV1beta1.KeyUsage{certificatesV1beta1.UsageKeyEncipherment, certificatesV1beta1.UsageServerAuth, certificatesV1beta1.UsageDigitalSignature},
			Username: WEBHOOKCSR,
			Groups:   []string{user.AllAuthenticated},
		},
	}, x509key, nil
}

// NewCSRAndKey generates a new key and CSR and that could be signed to create the given certificate
func NewCSRAndKey(config *cert.Config) (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	key, err := NewPrivateKey()
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to create private key")
	}

	csr, err := NewCSR(*config, key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to generate CSR")
	}

	return csr, key, nil
}

// NewCSR creates a new CSR
func NewCSR(cfg cert.Config, key crypto.Signer) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: cfg.Organization,
		},
		DNSNames:    cfg.AltNames.DNSNames,
		IPAddresses: cfg.AltNames.IPs,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)

	if err != nil {
		return nil, errors.Wrap(err, "failed to create a CSR")
	}

	return x509.ParseCertificateRequest(csrBytes)
}

func NewPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaKeySize)
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsExist(err) {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	log.Panicf("Failed to obtain the path status. Procedure %s：%v", path, err)
	return false, err
}

func MkdirPath(filename string) error {
	path, _ := filepath.Split(filename)
	exist, _ := PathExists(path)
	if !exist {
		if err := os.MkdirAll(path, os.ModePerm); err != nil {
			return err
		}
	}
	return nil
}

func writePki(filename, Type string, p []byte) error {
	if err := MkdirPath(filename); err != nil {
		return err
	}
	File, err := os.Create(filename)
	defer File.Close()
	if err != nil {
		return err
	}

	b := &pem.Block{Bytes: p, Type: Type}
	return pem.Encode(File, b)
}

func writeCert(filename string, p []byte) error {
	if err := MkdirPath(filename); err != nil {
		return err
	}
	File, err := os.Create(filename)
	defer File.Close()
	if err != nil {
		return err
	}
	_, err = File.Write(p)
	if err != nil {
		return err
	}
	return nil
}
