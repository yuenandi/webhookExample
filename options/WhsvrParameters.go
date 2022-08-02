package options

import (
	"github.com/spf13/pflag"
)

type WhSvrParameters struct {
	Port               int    // webhook server port
	CertFile           string // path to the x509 certificate for https
	KeyFile            string // path to the x509 private key matching `CertFile`
	Logv               int32
	AutoAuthentication bool
	Service            string
	Namespace          string
	KubeConfig         string
	IsDebug            bool
	Url                string
}

const (
	MutatePath = "/mutate"
)

var Parameters WhSvrParameters

func NewWhSvrParameters() {
	Parameters = WhSvrParameters{}
	Parameters.flagParse()
}

func (parameters *WhSvrParameters) flagParse() {
	// get command line parameters
	pflag.StringVar(&parameters.Service, "service", "webhookExample", "k8s资源service名称")
	pflag.StringVar(&parameters.Namespace, "namespace", "default", "命名空间")
	pflag.StringVar(&parameters.KubeConfig, "kubeconfig", parameters.KubeConfig, "模板路径")
	pflag.Int32VarP(&parameters.Logv, "log-v", "l", 4, "日志级别")
	pflag.BoolVar(&parameters.AutoAuthentication, "automatic-authentication", true, "是否自动构建证书")
	pflag.BoolVar(&parameters.IsDebug, "is-debug", false, "是否为开发模式")
	pflag.StringVar(&parameters.Url, "url", "", "开发机器地址")

	pflag.IntVar(&parameters.Port, "port", 6444, "Webhook server port.")
	pflag.StringVar(&parameters.CertFile, "tlsCertFile", "~/.webhookExample/pki/cert.pem", "File containing the x509 Certificate for HTTPS.")
	pflag.StringVar(&parameters.KeyFile, "tlsKeyFile", "~/.webhookExample/pki/key.pem", "File containing the x509 private key to --tlsCertFile.")

	pflag.Parse()
}
