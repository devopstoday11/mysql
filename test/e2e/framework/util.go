/*
Copyright The KubeDB Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package framework

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	api "kubedb.dev/apimachinery/apis/kubedb/v1alpha1"

	"github.com/appscode/go/log"
	"github.com/appscode/go/types"
	"github.com/aws/aws-sdk-go/aws"
	shell "github.com/codeskyblue/go-sh"
	. "github.com/onsi/gomega"
	promClient "github.com/prometheus/client_model/go"
	"github.com/prometheus/prom2json"
	core "k8s.io/api/core/v1"
	kerr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	kutil "kmodules.xyz/client-go"
	core_util "kmodules.xyz/client-go/core/v1"
	"kmodules.xyz/client-go/tools/portforward"
	kmon "kmodules.xyz/monitoring-agent-api/api/v1"
)

const (
	updateRetryInterval = 10 * 1000 * 1000 * time.Nanosecond
	maxAttempts         = 5
	mysqlUpMetric       = "mysql_up"
	metricsMatchedCount = 2
	mysqlVersionMetric  = "mysql_version_info"
)

func deleteInBackground() *metav1.DeleteOptions {
	policy := metav1.DeletePropagationBackground
	return &metav1.DeleteOptions{PropagationPolicy: &policy}
}

func deleteInForeground() *metav1.DeleteOptions {
	policy := metav1.DeletePropagationForeground
	return &metav1.DeleteOptions{PropagationPolicy: &policy}
}

func (f *Framework) CleanWorkloadLeftOvers() {
	// delete statefulset
	if err := f.kubeClient.AppsV1().StatefulSets(f.namespace).DeleteCollection(deleteInForeground(), metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			api.LabelDatabaseKind: api.ResourceKindMySQL,
		}).String(),
	}); err != nil && !kerr.IsNotFound(err) {
		fmt.Printf("error in deletion of Statefulset. Error: %v", err)
	}

	// delete pvc
	if err := f.kubeClient.CoreV1().PersistentVolumeClaims(f.namespace).DeleteCollection(deleteInForeground(), metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			api.LabelDatabaseKind: api.ResourceKindMySQL,
		}).String(),
	}); err != nil && !kerr.IsNotFound(err) {
		fmt.Printf("error in deletion of PVC. Error: %v", err)
	}

	// delete secret
	if err := f.kubeClient.CoreV1().Secrets(f.namespace).DeleteCollection(deleteInForeground(), metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			api.LabelDatabaseKind: api.ResourceKindMySQL,
		}).String(),
	}); err != nil && !kerr.IsNotFound(err) {
		fmt.Printf("error in deletion of Secret. Error: %v", err)
	}
}

func (f *Framework) WaitUntilPodRunningBySelector(mysql *api.MySQL) error {
	return core_util.WaitUntilPodRunningBySelector(
		f.kubeClient,
		mysql.Namespace,
		&metav1.LabelSelector{
			MatchLabels: mysql.OffshootSelectors(),
		},
		int(types.Int32(mysql.Spec.Replicas)),
	)
}

func (f *Framework) EventuallyWipedOut(meta metav1.ObjectMeta) GomegaAsyncAssertion {
	return Eventually(
		func() error {
			labelMap := map[string]string{
				api.LabelDatabaseName: meta.Name,
				api.LabelDatabaseKind: api.ResourceKindMySQL,
			}
			labelSelector := labels.SelectorFromSet(labelMap)

			// check if pvcs is wiped out
			pvcList, err := f.kubeClient.CoreV1().PersistentVolumeClaims(meta.Namespace).List(
				metav1.ListOptions{
					LabelSelector: labelSelector.String(),
				},
			)
			if err != nil {
				return err
			}
			if len(pvcList.Items) > 0 {
				return fmt.Errorf("PVCs have not wiped out yet")
			}

			// check if secrets are wiped out
			secretList, err := f.kubeClient.CoreV1().Secrets(meta.Namespace).List(
				metav1.ListOptions{
					LabelSelector: labelSelector.String(),
				},
			)
			if err != nil {
				return err
			}
			if len(secretList.Items) > 0 {
				return fmt.Errorf("secrets have not wiped out yet")
			}

			// check if appbinds are wiped out
			appBindingList, err := f.appCatalogClient.AppBindings(meta.Namespace).List(
				metav1.ListOptions{
					LabelSelector: labelSelector.String(),
				},
			)
			if err != nil {
				return err
			}
			if len(appBindingList.Items) > 0 {
				return fmt.Errorf("appBindings have not wiped out yet")
			}

			return nil
		},
		time.Minute*5,
		time.Second*5,
	)
}

func (f *Framework) AddMonitor(obj *api.MySQL) {
	obj.Spec.Monitor = &kmon.AgentSpec{
		Prometheus: &kmon.PrometheusSpec{
			Exporter: &kmon.PrometheusExporterSpec{
				Port:            api.PrometheusExporterPortNumber,
				Resources:       core.ResourceRequirements{},
				SecurityContext: nil,
			},
		},
		Agent: kmon.AgentPrometheus,
	}
}

//VerifyExporter uses metrics from given URL
//and check against known key and value
//to verify the connection is functioning as intended
func (f *Framework) VerifyExporter(meta metav1.ObjectMeta) error {
	tunnel, err := f.ForwardToPort(meta, fmt.Sprintf("%v-0", meta.Name), aws.Int(api.PrometheusExporterPortNumber))
	if err != nil {
		log.Infoln(err)
		return err
	}
	defer tunnel.Close()
	return wait.PollImmediate(time.Second, kutil.ReadinessTimeout, func() (bool, error) {
		metricsURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", tunnel.Local)
		mfChan := make(chan *promClient.MetricFamily, 1024)
		transport := makeTransport()

		err := prom2json.FetchMetricFamilies(metricsURL, mfChan, transport)
		if err != nil {
			log.Infoln(err)
			return false, nil
		}

		var count = 0
		for mf := range mfChan {
			if mf.Metric != nil && mf.Metric[0].Gauge != nil && mf.Metric[0].Gauge.Value != nil {
				if *mf.Name == mysqlVersionMetric && strings.Contains(DBCatalogName, *mf.Metric[0].Label[0].Value) {
					count++
				} else if *mf.Name == mysqlUpMetric && int(*mf.Metric[0].Gauge.Value) > 0 {
					count++
				}
			}
		}

		if count != metricsMatchedCount {
			return false, nil
		}
		log.Infoln("Found ", count, " metrics out of ", metricsMatchedCount)
		return true, nil
	})
}

func makeTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

func (f *Framework) ForwardToPort(meta metav1.ObjectMeta, clientPodName string, port *int) (*portforward.Tunnel, error) {
	var defaultPort = api.PrometheusExporterPortNumber
	if port != nil {
		defaultPort = *port
	}

	tunnel := portforward.NewTunnel(
		f.kubeClient.CoreV1().RESTClient(),
		f.restConfig,
		meta.Namespace,
		clientPodName,
		defaultPort,
	)
	if err := tunnel.ForwardPort(); err != nil {
		return nil, err
	}

	return tunnel, nil
}

func isDebugTarget(containers []core.Container) (bool, []string) {
	for _, c := range containers {
		if c.Name == "stash" || c.Name == "stash-init" {
			return true, []string{"-c", c.Name}
		} else if strings.HasPrefix(c.Name, "update-status") {
			return true, []string{"--all-containers"}
		}
	}
	return false, nil
}

func (f *Framework) PrintDebugHelpers(mysqlName string, replicas int) {
	sh := shell.NewSession()

	fmt.Println("\n======================================[ Apiservices ]===================================================")
	if err := sh.Command("/usr/bin/kubectl", "get", "apiservice", "v1alpha1.mutators.kubedb.com", "-o=jsonpath=\"{.status}\"").Run(); err != nil {
		fmt.Println(err)
	}
	fmt.Println()
	if err := sh.Command("/usr/bin/kubectl", "get", "apiservice", "v1alpha1.validators.kubedb.com", "-o=jsonpath=\"{.status}\"").Run(); err != nil {
		fmt.Println(err)
	}

	fmt.Println("\n======================================[ Describe Job ]===================================================")
	if err := sh.Command("/usr/bin/kubectl", "describe", "job", "-n", f.Namespace()).Run(); err != nil {
		fmt.Println(err)
	}

	fmt.Println("\n===============[ Debug info for Stash sidecar/init-container/backup job/restore job ]===================")
	if pods, err := f.kubeClient.CoreV1().Pods(f.Namespace()).List(metav1.ListOptions{}); err == nil {
		for _, pod := range pods.Items {
			debugTarget, containerArgs := isDebugTarget(append(pod.Spec.InitContainers, pod.Spec.Containers...))
			if debugTarget {
				fmt.Printf("\n--------------- Describe Pod: %s -------------------\n", pod.Name)
				if err := sh.Command("/usr/bin/kubectl", "describe", "po", "-n", f.Namespace(), pod.Name).Run(); err != nil {
					fmt.Println(err)
				}

				fmt.Printf("\n---------------- Log from Pod: %s ------------------\n", pod.Name)
				logArgs := []interface{}{"logs", "-n", f.Namespace(), pod.Name}
				for i := range containerArgs {
					logArgs = append(logArgs, containerArgs[i])
				}
				err = sh.Command("/usr/bin/kubectl", logArgs...).
					Command("cut", "-f", "4-", "-d ").
					Command("awk", `{$2=$2;print}`).
					Command("uniq").Run()
				if err != nil {
					fmt.Println(err)
				}
			}
		}
	} else {
		fmt.Println(err)
	}

	fmt.Println("\n======================================[ Describe Pod ]===================================================")
	if err := sh.Command("/usr/bin/kubectl", "describe", "po", "-n", f.Namespace()).Run(); err != nil {
		fmt.Println(err)
	}

	fmt.Println("\n======================================[ Describe statefulsets ]===================================================")
	if err := sh.Command("/usr/bin/kubectl", "describe", "sts", "-n", f.Namespace()).Run(); err != nil {
		fmt.Println(err)
	}

	fmt.Println("\n======================================[ Describe MySQL ]===================================================")
	if err := sh.Command("/usr/bin/kubectl", "describe", "mysql", mysqlName, "-n", f.Namespace()).Run(); err != nil {
		fmt.Println(err)
	}

	fmt.Println("\n======================================[ MySQL Server Log ]===================================================")
	for i := 0; i < replicas; i++ {
		if err := sh.Command("/usr/bin/kubectl", "logs", fmt.Sprintf("%s-%d", mysqlName, i), "-n", f.Namespace()).Run(); err != nil {
			fmt.Println(err)
		}
	}

	fmt.Println("\n======================================[ Describe BackupSession ]==========================================")
	if err := sh.Command("/usr/bin/kubectl", "describe", "backupsession", "-n", f.Namespace()).Run(); err != nil {
		fmt.Println(err)
	}

	fmt.Println("\n======================================[ Describe RestoreSession ]==========================================")
	if err := sh.Command("/usr/bin/kubectl", "describe", "restoresession", "-n", f.Namespace()).Run(); err != nil {
		fmt.Println(err)
	}
}
