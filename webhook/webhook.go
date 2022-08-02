package webhook

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/wI2L/jsondiff"
	"github.com/webhookExample/options"
	"io/ioutil"
	"net/http"
	"sigs.k8s.io/yaml"
	"strings"
	"time"

	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	v1 "k8s.io/kubernetes/pkg/apis/core/v1"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

const (
	admissionWebhookAnnotationStatusKey = "webhook-example.github.com/status"
	admissionWebhookLabelMutateKey      = "webhook-example.github.com/app"
)

var (
	ignoredNamespaces = []string{
		metav1.NamespaceSystem,
		metav1.NamespacePublic,
	}

	addLabels = map[string]string{
		admissionWebhookLabelMutateKey: "true",
	}

	addAnnotations = map[string]string{
		admissionWebhookAnnotationStatusKey: "mutated",
	}
)

type WebhookServer struct {
	Server *http.Server
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
	// defaulting with webhooks:
	// https://github.com/kubernetes/kubernetes/issues/57982
	_ = v1.AddToScheme(runtimeScheme)
}

// Serve method for webhook server
func (whsvr *WebhookServer) Serve(w http.ResponseWriter, r *http.Request) {

	//读取从ApiServer过来的数据放到body
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		logString := "empty body"
		log.Warnf(logString)
		//返回状态码400
		//如果在Apiserver调用此Webhook返回是400，说明APIServer自己传过来的数据是空
		http.Error(w, logString, http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		logString := fmt.Sprintf("Content-Type=%s, expect `application/json`", contentType)
		log.Warnf(logString)
		//如果在Apiserver调用此Webhook返回是415，说明APIServer自己传过来的数据不是json格式，处理不了
		http.Error(w, logString, http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		//组装错误信息
		logString := fmt.Sprintf("\nCan't decode body,error info is :  %s", err.Error())
		log.Errorln(logString)
		//返回错误信息，形式表现为资源创建会失败，
		admissionResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: logString,
			},
		}
	} else {
		if r.URL.Path == options.MutatePath {
			admissionResponse = whsvr.mutate(&ar)

			admissionReview := v1beta1.AdmissionReview{}
			if admissionResponse != nil {
				admissionReview.Response = admissionResponse
				if ar.Request != nil {
					admissionReview.Response.UID = ar.Request.UID
				}
			}

			resp, err := json.Marshal(admissionReview)
			if err != nil {
				logString := fmt.Sprintf("\nCan't encode response: %v", err)
				log.Errorln(logString)
				http.Error(w, logString, http.StatusInternalServerError)
			}
			log.Infoln("Ready to write reponse ...")
			if _, err := w.Write(resp); err != nil {
				logString := fmt.Sprintf("\nCan't write response: %v", err)
				log.Errorln(logString)
				http.Error(w, logString, http.StatusInternalServerError)
			}

			//东八区时间
			datetime := time.Now().In(time.FixedZone("GMT", 8*3600)).Format("2006-01-02 15:04:05")
			logString := fmt.Sprintf("======%s ended Admission already writed to reponse======", datetime)
			//最后打印日志
			log.Infof(logString)
		}
	}
}

//处理逻辑
func (whsvr *WebhookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	var (
		objectMeta                      *metav1.ObjectMeta
		resourceNamespace, resourceName string
		deployment                      appsv1.Deployment
	)

	log.Infof(fmt.Sprintf("======begin Admission for Namespace=[%v], Kind=[%v], Name=[%v]======", req.Namespace, req.Kind.Kind, req.Name))

	switch req.Kind.Kind {
	// 支持Deployment
	case "Deployment":
		if err := json.Unmarshal(req.Object.Raw, &deployment); err != nil {
			log.Errorln(fmt.Sprintf("\nCould not unmarshal raw object: %v", err))
			return &v1beta1.AdmissionResponse{
				Result: &metav1.Status{
					Message: err.Error(),
				},
			}
		}
		resourceName, resourceNamespace, objectMeta, deployment = deployment.Name, deployment.Namespace, &deployment.ObjectMeta, deployment
	//其他不支持的类型
	default:
		msg := fmt.Sprintf("\nNot support for this Kind of resource  %v", req.Kind.Kind)
		log.Warnf(msg)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: msg,
			},
		}
	}

	//跳过不进行处理的情况
	if !mutationRequired(ignoredNamespaces, objectMeta) {
		log.Infoln(fmt.Sprintf("Skipping validation for %s/%s due to policy check", resourceNamespace, resourceName))
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}
	//开始处理
	patchBytes, err := createPatch(deployment, addAnnotations, addLabels)
	if err != nil {
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	log.Debugf(fmt.Sprintf("AdmissionResponse: patch=%v\n", string(patchBytes)))
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

func admissionRequired(ignoredList []string, metadata *metav1.ObjectMeta) bool {
	// skip special kubernetes system namespaces
	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			log.Infof("Skip validation for %v for it's in special namespace:%v", metadata.Name, metadata.Namespace)
			return false
		}
	}

	var required bool

	labels := metadata.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}

	switch strings.ToLower(labels[admissionWebhookLabelMutateKey]) {
	default:
		required = true
	case "n", "no", "false", "off":
		log.Infof("Skip validation for %v for it's in special label: %s:%s", metadata.Name, admissionWebhookLabelMutateKey, labels[admissionWebhookLabelMutateKey])
		return false
	}
	return required
}

//不处理情况：特定命名空间；已经处理的；label：webhook-example.github.com/app=false的
func mutationRequired(ignoredList []string, metadata *metav1.ObjectMeta) bool {
	required := admissionRequired(ignoredList, metadata)
	if !required {
		return false
	}
	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	status := annotations[admissionWebhookAnnotationStatusKey]

	if strings.ToLower(status) == "mutated" {
		required = false
	}

	log.Infof("Mutation policy for %v/%v: required:%v", metadata.Namespace, metadata.Name, required)
	return required
}

//拼接PatchJson
func createPatch(deployment appsv1.Deployment, addAnnotations map[string]string, addLabels map[string]string) ([]byte, error) {

	var patches []patchOperation
	objectMeta := deployment.ObjectMeta
	labels := objectMeta.Labels
	annotations := objectMeta.Annotations
	labelsPatch := updateLabels(labels, addLabels)
	annotationsPatch := updateAnnotation(annotations, addAnnotations)
	containersPatch := updateContainers(addContainer, deployment)

	patches = append(patches, labelsPatch...)
	patches = append(patches, annotationsPatch...)
	patches = append(patches, containersPatch...)

	//打印出来看一下
	patchYaml, err := yaml.Marshal(patches)
	if err != nil {
		log.Error(fmt.Sprintf("Patch TO PatchYaml Failure: %s", err))
	}
	log.Debugf("修改内容如下：\n%s", string(patchYaml))
	return json.Marshal(patches)
}

func updateAnnotation(target map[string]string, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		if target == nil || target[key] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + key,
				Value: value,
			})
		}
	}
	return patch
}

func updateLabels(target map[string]string, added map[string]string) (patch []patchOperation) {
	values := make(map[string]string)
	for key, value := range added {
		if target == nil || target[key] == "" {
			values[key] = value
		}
	}
	patch = append(patch, patchOperation{
		Op:    "add",
		Path:  "/metadata/labels",
		Value: values,
	})
	return patch
}

var addContainer = []corev1.Container{
	{
		Name:    "side-car",
		Image:   "busybox",
		Command: []string{"/bin/sleep", "infinity"},
	},
}

func updateContainers(addContainer []corev1.Container, deployment appsv1.Deployment) (patch []patchOperation) {
	currentDeployment := deployment.DeepCopy()
	containers := currentDeployment.Spec.Template.Spec.Containers
	containers = append(containers, addContainer...)
	currentDeployment.Spec.Template.Spec.Containers = containers
	diffPatch, err := jsondiff.Compare(deployment, currentDeployment)
	if err != nil {
		log.Error("")
	}
	for _, v := range diffPatch {
		addPatch := patchOperation{
			Op:    v.Type,
			Value: v.Value,
			Path:  string(v.Path),
		}
		patch = append(patch, addPatch)
	}
	return patch
}
