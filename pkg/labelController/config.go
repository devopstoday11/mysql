package labelController

import (
	"os"
	"time"

	"kubedb.dev/apimachinery/apis/kubedb/v1alpha1"
	cs "kubedb.dev/apimachinery/client/clientset/versioned"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	mysqlUser = "root"

	KeyMySQLUser     = "username"
	KeyMySQLPassword = "password"
	DatabaseName     = "mysql"
	Primary          = "primary"
	Secondary        = "Secondary"
	LabelRole        = v1alpha1.MySQLKey + "/role"
)

type LabelerConfig struct {
	KubeInformerFactory informers.SharedInformerFactory
	ClientConfig        *rest.Config
	KubeClient          kubernetes.Interface
	DBClient            cs.Interface

	OperatorNamespace string
	ResyncPeriod      time.Duration
	MaxNumRequeues    int
	NumThreads        int
	WatchNamespace    string
}

func (c *LabelerConfig) New() (*LabelController, error) {
	hostName, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	ctrl := NewLabelController(
		c.KubeInformerFactory,
		c.ClientConfig,
		c.KubeClient,
		c.DBClient,
		c.MaxNumRequeues,
		c.NumThreads,
		c.WatchNamespace,
		hostName,
	)

	ctrl.tweakListOptions = func(options *metav1.ListOptions) {
		options.FieldSelector = ctrl.selector.String()
	}

	ctrl.initWatcher()

	return ctrl, nil
}
