package labelController

import (
	"time"

	cs "kubedb.dev/apimachinery/client/clientset/versioned"

	"github.com/appscode/go/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	v12 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	corev1 "k8s.io/kubernetes/pkg/apis/core"
	"kmodules.xyz/client-go/tools/queue"
)

type LabelController struct {
	kubeInformerFactory informers.SharedInformerFactory
	clientConfig        *rest.Config
	kubeClient          kubernetes.Interface
	dbClient            cs.Interface

	maxNumRequeues int
	numThreads     int
	watchNamespace string

	// selector for event-handler of MySQL Pod
	selector fields.Selector
	// tweakListOptions for watcher
	tweakListOptions func(*metav1.ListOptions)

	// MySQL Pod
	podQueue    *queue.Worker
	podInformer cache.SharedIndexInformer
	podLister   v1.PodLister

	hostName string
}

func NewLabelController(
	kubeInformerFactory informers.SharedInformerFactory,
	clientConfig *rest.Config,
	kubeClient kubernetes.Interface,
	dbClient cs.Interface,
	maxNumRequeues int,
	numThreads int,
	watchNamespace string,
	hostName string,
) *LabelController {
	return &LabelController{
		kubeInformerFactory: kubeInformerFactory,
		clientConfig:        clientConfig,
		kubeClient:          kubeClient,
		dbClient:            dbClient,

		maxNumRequeues: maxNumRequeues,
		numThreads:     numThreads,
		//selector:       fields.OneTermEqualSelector("metadata.name", "my-group-2"),
		selector:       fields.OneTermEqualSelector("metadata.name", hostName),
		watchNamespace: watchNamespace,
	}
}

func (lc *LabelController) InitInformer() cache.SharedIndexInformer {
	return lc.kubeInformerFactory.InformerFor(&corev1.Pod{}, func(client kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v12.NewFilteredPodInformer(
			client,
			lc.watchNamespace,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			lc.tweakListOptions,
		)
	})
}

// Blocks caller. Intended to be called as a Go routine.
func (lc *LabelController) RunLabelController(stopCh <-chan struct{}) {
	go lc.StartAndRunController(stopCh)

	<-stopCh
}

// StartAndRunControllers starts InformerFactory and runs queue.worker
func (lc *LabelController) StartAndRunController(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()

	lc.kubeInformerFactory.Start(stopCh)

	// Wait for all involved caches to be synced, before processing items from the queue is started
	for t, v := range lc.kubeInformerFactory.WaitForCacheSync(stopCh) {
		if !v {
			log.Fatalf("%v timed out waiting for caches to sync", t)
			return
		}
	}
	lc.Run(stopCh)

	<-stopCh
}

// Run runs queue.worker
func (lc *LabelController) Run(stopCh <-chan struct{}) {
	lc.podQueue.Run(stopCh)

}
