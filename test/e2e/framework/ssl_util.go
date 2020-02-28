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
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	api "kubedb.dev/apimachinery/apis/kubedb/v1alpha1"

	_ "github.com/go-sql-driver/mysql"
	sql_driver "github.com/go-sql-driver/mysql"
	"github.com/go-xorm/xorm"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kmodules.xyz/client-go/tools/portforward"
)

const (
	TLSSkibVerify              = "skip-verify"
	TLSTrue                    = "true"
	TLSFalse                   = "false"
	RequiredSecureTransportON  = "ON"
	RequiredSecureTransportOFF = "OFF"
	TLSCustomConfig            = "custom"
)

func (f *Framework) EventuallyCheckSSLSettings(meta metav1.ObjectMeta, dbName, params, config string) GomegaAsyncAssertion {
	sslConfigVarPair := strings.Split(config, "=")
	sql := fmt.Sprintf("SHOW VARIABLES LIKE '%s';", sslConfigVarPair[0])
	return Eventually(
		func() []map[string][]byte {
			tunnel, err := f.forwardPort(meta, 0)
			if err != nil {
				return nil
			}
			defer tunnel.Close()

			en, err := f.getMySQLClientWithConfiguredRootCAs(meta, tunnel, dbName, params)
			if err != nil {
				return nil
			}
			defer en.Close()

			results, err := en.Query(sql)
			if err != nil {
				return nil
			}
			return results
		},
		time.Minute*5,
		time.Second*5,
	)
}

func (f *Framework) EventuallyCreateUserWithRequiredSSL(meta metav1.ObjectMeta, dbName, params string) GomegaAsyncAssertion {
	sql := fmt.Sprintf("CREATE USER '%s'@'%s' IDENTIFIED BY '%s' REQUIRE SSL;", mysqlRequiredSSLUser, "%", mysqlRequiredSSLUserPassword)
	privilege := "GRANT ALL ON mysql.* TO 'user'@'%';"
	flush := "FLUSH PRIVILEGES;"
	return Eventually(
		func() bool {
			tunnel, err := f.forwardPort(meta, 0)
			if err != nil {
				return false
			}
			defer tunnel.Close()

			en, err := f.getMySQLClientWithConfiguredRootCAs(meta, tunnel, dbName, params)
			if err != nil {
				return false
			}
			defer en.Close()
			// create new user
			if _, err = en.Query(sql); err != nil {
				return false
			}
			// grand all permission for the new user
			if _, err = en.Query(privilege); err != nil {
				return false
			}

			// flush privilege
			if _, err = en.Query(flush); err != nil {
				return false
			}

			return true
		},
		time.Minute*10,
		time.Second*20,
	)
}

func (f *Framework) EventuallyCheckReqiredSSLUserConnection(meta metav1.ObjectMeta, dbName, params string) GomegaAsyncAssertion {
	return Eventually(
		func() bool {
			tunnel, err := f.forwardPort(meta, 0)
			if err != nil {
				return false
			}
			defer tunnel.Close()

			en, err := f.getMySQLClientWithConfiguredClientCerts(meta, tunnel, dbName, params)
			if err != nil {
				return false
			}
			defer en.Close()

			if err = en.Ping(); err != nil {
				return false
			}
			return true
		},
		time.Minute*10,
		time.Second*20,
	)
}

func (f *Framework) EventuallyCheckRootUserConnection(meta metav1.ObjectMeta, dbName, params string) GomegaAsyncAssertion {
	return Eventually(
		func() bool {
			tunnel, err := f.forwardPort(meta, 0)
			if err != nil {
				return false
			}
			defer tunnel.Close()

			en, err := f.getMySQLClientWithConfiguredRootCAs(meta, tunnel, dbName, params)
			if err != nil {
				return false
			}
			defer en.Close()

			if err = en.Ping(); err != nil {
				return false
			}
			return true
		},
		time.Minute*10,
		time.Second*20,
	)
}

func (f *Framework) getMySQLClientWithConfiguredRootCAs(meta metav1.ObjectMeta, tunnel *portforward.Tunnel, dbName, params string) (*xorm.Engine, error) {
	mysql, err := f.GetMySQL(meta)
	if err != nil {
		return nil, err
	}
	pass, err := f.GetMySQLRootPassword(mysql)
	if err != nil {
		return nil, err
	}
	// get server-secret
	secret, err := f.kubeClient.CoreV1().Secrets(f.Namespace()).Get(fmt.Sprintf("%s-%s", meta.Name, api.MySQLServerCertSuffix), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	cacrt := secret.Data["ca.crt"]
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(cacrt)
	// tls custom setup
	err = sql_driver.RegisterTLSConfig(TLSCustomConfig, &tls.Config{
		RootCAs: certPool,
	})
	if err != nil {
		return nil, err
	}

	cnnstr := fmt.Sprintf("%s:%v@tcp(127.0.0.1:%v)/%s?%s", mysqlUser, pass, tunnel.Local, dbName, params)
	return xorm.NewEngine("mysql", cnnstr)
}

func (f *Framework) getMySQLClientWithConfiguredClientCerts(meta metav1.ObjectMeta, tunnel *portforward.Tunnel, dbName, params string) (*xorm.Engine, error) {
	// get server-secret
	serverSecret, err := f.kubeClient.CoreV1().Secrets(f.Namespace()).Get(fmt.Sprintf("%s-%s", meta.Name, api.MySQLServerCertSuffix), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	cacrt := serverSecret.Data["ca.crt"]
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(cacrt)

	// get client-secret
	clientSecret, err := f.kubeClient.CoreV1().Secrets(f.Namespace()).Get(fmt.Sprintf("%s-%s", meta.Name, api.MySQLClientCertSuffix), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	ccrt := clientSecret.Data["tls.crt"]
	ckey := clientSecret.Data["tls.key"]
	cert, err := tls.X509KeyPair(ccrt, ckey)
	if err != nil {
		return nil, err
	}
	var clientCert []tls.Certificate
	clientCert = append(clientCert, cert)

	// tls custom setup
	err = sql_driver.RegisterTLSConfig(TLSCustomConfig, &tls.Config{
		RootCAs:      certPool,
		Certificates: clientCert,
	})
	if err != nil {
		return nil, err
	}

	cnnstr := fmt.Sprintf("%v:%v@tcp(127.0.0.1:%v)/%s?%s", mysqlRequiredSSLUser, mysqlRequiredSSLUserPassword, tunnel.Local, dbName, params)
	return xorm.NewEngine("mysql", cnnstr)
}

func (f *Framework) EventuallyCreateTableWithSSLConnection(meta metav1.ObjectMeta, dbName, params string) GomegaAsyncAssertion {
	return Eventually(
		func() bool {
			tunnel, err := f.forwardPort(meta, 0)
			if err != nil {
				return false
			}
			defer tunnel.Close()

			en, err := f.getMySQLClientWithConfiguredRootCAs(meta, tunnel, dbName, params)
			if err != nil {
				return false
			}
			defer en.Close()

			if err := en.Ping(); err != nil {
				return false
			}

			return en.Sync(new(KubedbTable)) == nil
		},
		time.Minute*10,
		time.Second*20,
	)
}

func (f *Framework) EventuallyInsertRowWithSSLConnection(meta metav1.ObjectMeta, dbName, params string, clientPodIndex, total int) GomegaAsyncAssertion {
	count := 0
	return Eventually(
		func() bool {
			tunnel, err := f.forwardPort(meta, clientPodIndex)
			if err != nil {
				return false
			}
			defer tunnel.Close()

			en, err := f.getMySQLClientWithConfiguredRootCAs(meta, tunnel, dbName, params)
			if err != nil {
				return false
			}
			defer en.Close()

			if err := en.Ping(); err != nil {
				return false
			}

			for i := count; i < total; i++ {
				if _, err := en.Insert(&KubedbTable{
					Name: fmt.Sprintf("KubedbName-%v", i),
				}); err != nil {
					return false
				}
				count++
			}
			return true
		},
		time.Minute*10,
		time.Second*10,
	)
}

func (f *Framework) EventuallyCountRowWithSSLConnection(meta metav1.ObjectMeta, dbName, params string, clientPodIndex int) GomegaAsyncAssertion {
	return Eventually(
		func() int {
			tunnel, err := f.forwardPort(meta, clientPodIndex)
			if err != nil {
				return -1
			}
			defer tunnel.Close()

			en, err := f.getMySQLClientWithConfiguredRootCAs(meta, tunnel, dbName, params)
			if err != nil {
				return -1
			}
			defer en.Close()

			if err := en.Ping(); err != nil {
				return -1
			}

			kubedb := new(KubedbTable)
			total, err := en.Count(kubedb)
			if err != nil {
				return -1
			}
			return int(total)
		},
		time.Minute*10,
		time.Second*20,
	)
}
