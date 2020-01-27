package labelController

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"kubedb.dev/apimachinery/apis/kubedb/v1alpha1"

	"github.com/appscode/go/log"
	"github.com/golang/glog"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	v1 "kmodules.xyz/client-go/core/v1"
	meta_util "kmodules.xyz/client-go/meta"
	"kmodules.xyz/client-go/tools/queue"
)

func (lc *LabelController) initWatcher() {
	lc.podInformer = lc.InitInformer()
	lc.podQueue = queue.New("Pod", lc.maxNumRequeues, lc.numThreads, lc.podLabeler)
	lc.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if pod, ok := obj.(*core.Pod); ok {
				queue.Enqueue(lc.podQueue.GetQueue(), pod)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod, ok := oldObj.(*core.Pod)
			if !ok {
				glog.Errorf("Invalid Pod Object")
				return
			}
			newPod, ok := newObj.(*core.Pod)
			if !ok {
				glog.Errorf("Invalid Pod Object")
				return
			}
			if !reflect.DeepEqual(&oldPod, &newPod) {
				queue.Enqueue(lc.podQueue.GetQueue(), newPod)
			}
		},
	})
	lc.podLister = lc.kubeInformerFactory.Core().V1().Pods().Lister()
}

func (lc *LabelController) podLabeler(key string) error {
	log.Debugln("Started processing, key:", key)
	obj, exists, err := lc.podInformer.GetIndexer().GetByKey(key)
	if err != nil {
		log.Errorf("Fetching object with key %s from store failed with %v", key, err)
		return err
	}

	if !exists {
		log.Debugf("Pod %s does not exist anymore", key)
	} else {

		pod := obj.(*core.Pod).DeepCopy()

		log.Debugf("Pod %s does not exist anymore", pod.Name)

		if meta_util.HasKey(pod.Labels, v1alpha1.LabelDatabaseKind) &&
			meta_util.HasKey(pod.Labels, v1alpha1.LabelDatabaseName) {
			isPrimary, err := lc.checkPrimary(pod.ObjectMeta)
			if err != nil {
				return err
			}
			if isPrimary {
				if err := lc.ensureRoleAsPrimary(pod); err != nil {
					return err
				}
			} else {
				if err := lc.removeRoleFromLabels(pod); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (lc *LabelController) checkPrimary(ObjMeta metav1.ObjectMeta) (bool, error) {
	user := os.Getenv(KeyMySQLUser)
	if user == "" {
		return false, fmt.Errorf("missing 'MYSQL_ROOT_USERNAME' env in MySQL Pod")
	}
	password := os.Getenv(KeyMySQLPassword)
	//user := "root"
	//password := "_oQXukNhB-E4FOxC"

	// MySQL query to check master
	query := `SELECT MEMBER_HOST FROM performance_schema.replication_group_members
	INNER JOIN performance_schema.global_status ON (MEMBER_ID = VARIABLE_VALUE)
	WHERE VARIABLE_NAME='group_replication_primary_member';`
	result, err := lc.queryInMySQLDatabase(ObjMeta, user, password, query)
	if err != nil {
		return false, err
	}

	host := string(result[0]["MEMBER_HOST"])
	hostName := strings.Split(host, ".")[0]

	if hostName == ObjMeta.Name {
		return true, nil
	}

	return false, nil
}

func (ls *LabelController) ensureRoleAsPrimary(pod *core.Pod) error {
	_, _, err := v1.PatchPod(ls.kubeClient, pod, func(in *core.Pod) *core.Pod {
		in.Labels = v1.UpsertMap(in.Labels, map[string]string{
			LabelRole: Primary,
		})
		return in
	})
	return err
}

func (ls *LabelController) removeRoleFromLabels(pod *core.Pod) error {
	_, _, err := v1.PatchPod(ls.kubeClient, pod, func(in *core.Pod) *core.Pod {
		labels := pod.Labels
		delete(labels, LabelRole)
		in.Labels = labels
		return in
	})
	return err
}
