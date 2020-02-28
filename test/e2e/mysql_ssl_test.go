package e2e_test

import (
	"fmt"

	api "kubedb.dev/apimachinery/apis/kubedb/v1alpha1"
	"kubedb.dev/mysql/test/e2e/framework"
	"kubedb.dev/mysql/test/e2e/matcher"

	"github.com/appscode/go/log"
	"github.com/appscode/go/types"
	_ "github.com/go-sql-driver/mysql"
	cm_api "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	core "k8s.io/api/core/v1"
	kerr "k8s.io/apimachinery/pkg/api/errors"
)

var _ = Describe("MySQL SSL", func() {
	var (
		err              error
		f                *framework.Invocation
		mysql            *api.MySQL
		garbageCASecrets []*core.Secret
		dbName           string
		skipMessage      string
		issuer           *cm_api.Issuer
	)

	var addIssuerRef = func() {
		//create cert-manager ca secret
		clientCASecret := f.SelfSignedCASecret(mysql.ObjectMeta)
		err := f.CreateSecret(clientCASecret)
		Expect(err).NotTo(HaveOccurred())
		garbageCASecrets = append(garbageCASecrets, clientCASecret)
		//create issuer
		issuer = f.IssuerForMySQL(mysql.ObjectMeta, clientCASecret.ObjectMeta)
		err = f.CreateIssuer(issuer)
		Expect(err).NotTo(HaveOccurred())
		// configure TLS issuer to MYSQL CRD
		mysql.Spec.TLS = &api.TLSConfig{
			IssuerRef: &core.TypedLocalObjectReference{
				Name:     issuer.Name,
				Kind:     issuer.Kind,
				APIGroup: types.StringP(cm_api.SchemeGroupVersion.Group), //cert-manger.io
			},
			Certificate: &api.CertificateSpec{
				Organization: []string{
					"kubedb:server",
				},
				DNSNames: []string{
					"localhost",
					"127.0.0.1",
				},
				IPAddresses: []string{
					"localhost",
					"127.0.0.1",
				},
			},
		}
	}

	var checkClientConnectionForRequiredSSLUser = func() {
		By("checking required ssl user connection with tls: skip-verify")
		f.EventuallyCheckReqiredSSLUserConnection(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSSkibVerify)).Should(BeTrue())

		By("checking required ssl user connection with tls: custom(for self signed certificate)")
		f.EventuallyCheckReqiredSSLUserConnection(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSCustomConfig)).Should(BeTrue())
	}

	var checkClientConnectionForRootUser = func(requireSecureTransport string) {
		By("checking root user connection with tls: skip-verify")
		f.EventuallyCheckRootUserConnection(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSSkibVerify)).Should(BeTrue())

		By("checking root user connection with tls: custom(for self signed certificate)")
		f.EventuallyCheckRootUserConnection(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSCustomConfig)).Should(BeTrue())

		if requireSecureTransport == framework.RequiredSecureTransportOFF {
			By("checking root user connection with tls: false")
			f.EventuallyCheckRootUserConnection(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSFalse)).Should(BeTrue())
		}
	}

	var createAndWaitForRunning = func(requireSecureTransport string) {
		// all the MySQL here has TLS, hence needs IssuerRef
		addIssuerRef()

		By("Create MySQL: " + mysql.Name)
		err = f.CreateMySQL(mysql)
		Expect(err).NotTo(HaveOccurred())

		By("Wait for Running mysql")
		f.EventuallyMySQLRunning(mysql.ObjectMeta).Should(BeTrue())

		By("Wait for AppBinding to create")
		f.EventuallyAppBinding(mysql.ObjectMeta).Should(BeTrue())

		By("Check valid AppBinding Specs")
		err := f.CheckAppBindingSpec(mysql.ObjectMeta)
		Expect(err).NotTo(HaveOccurred())

		checkClientConnectionForRootUser(requireSecureTransport)

		By("Checking MySQL SSL server settings")
		sslConfigVar := []string{
			fmt.Sprintf("require_secure_transport=%s", requireSecureTransport),
			"have_ssl=YES",
			"have_openssl=YES",
			// in MySQL, certs are stored in "/etc/mysql/certs" path
			"ssl_ca=/etc/mysql/certs/ca.crt",
			"ssl_cert=/etc/mysql/certs/server.crt",
			"ssl_key=/etc/mysql/certs/server.key",
		}
		for _, cfg := range sslConfigVar {
			f.EventuallyCheckSSLSettings(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSCustomConfig), cfg).Should(matcher.HaveSSL(cfg))
		}

		// create a mysql user with required SSL
		By("Create mysql user with required SSL")
		f.EventuallyCreateUserWithRequiredSSL(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSCustomConfig)).Should(BeTrue())

		checkClientConnectionForRequiredSSLUser()
	}

	var testRequireSSLTrue = func() {
		if skipMessage != "" {
			Skip(skipMessage)
		}
		// Create MySQL
		createAndWaitForRunning(framework.RequiredSecureTransportON)

		By("Creating Table")
		f.EventuallyCreateTableWithSSLConnection(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSCustomConfig)).Should(BeTrue())

		By("Inserting Rows")
		f.EventuallyInsertRowWithSSLConnection(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSCustomConfig), 0, 3).Should(BeTrue())

		By("Checking Row Count of Table")
		f.EventuallyCountRowWithSSLConnection(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSCustomConfig), 0).Should(Equal(3))
	}

	var testRequireSSLFalse = func() {
		if skipMessage != "" {
			Skip(skipMessage)
		}
		// Create MySQL
		createAndWaitForRunning(framework.RequiredSecureTransportOFF)

		By("Creating Table")
		f.EventuallyCreateTableWithSSLConnection(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSCustomConfig)).Should(BeTrue())

		By("Inserting Rows")
		f.EventuallyInsertRowWithSSLConnection(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSCustomConfig), 0, 3).Should(BeTrue())

		By("Checking Row Count of Table")
		f.EventuallyCountRowWithSSLConnection(mysql.ObjectMeta, dbName, fmt.Sprintf("tls=%s", framework.TLSCustomConfig), 0).Should(Equal(3))
	}

	var deleteTestResource = func() {

		if mysql == nil {
			log.Infoln("Skipping cleanup. Reason: mysql is nil")
			return
		}

		By("Check if mysql " + mysql.Name + " exists.")
		my, err := f.GetMySQL(mysql.ObjectMeta)
		if err != nil {
			if kerr.IsNotFound(err) {
				// MySQL was not created. Hence, rest of cleanup is not necessary.
				return
			}
			Expect(err).NotTo(HaveOccurred())
		}

		By("Update mysql to set spec.terminationPolicy = WipeOut")
		_, err = f.PatchMySQL(my.ObjectMeta, func(in *api.MySQL) *api.MySQL {
			in.Spec.TerminationPolicy = api.TerminationPolicyWipeOut
			return in
		})
		Expect(err).NotTo(HaveOccurred())

		By("Delete mysql")
		err = f.DeleteMySQL(mysql.ObjectMeta)
		if err != nil {
			if kerr.IsNotFound(err) {
				log.Infoln("Skipping rest of the cleanup. Reason: MySQL does not exist.")
				return
			}
			Expect(err).NotTo(HaveOccurred())
		}

		By("Wait for mysql to be deleted")
		f.EventuallyMySQL(mysql.ObjectMeta).Should(BeFalse())

		By("Delete Issuer")
		err = f.DeleteIssuer(issuer.ObjectMeta)
		Expect(err).NotTo(HaveOccurred())

		By("Delete CA secret")
		f.DeleteGarbageCASecrets(garbageCASecrets)
	}

	var verifyExporter = func() {
		if skipMessage != "" {
			Skip(skipMessage)
		}
		By("Add monitoring configurations to mysql")
		f.AddMonitor(mysql)
		// Create MySQL
		createAndWaitForRunning(framework.RequiredSecureTransportON)
		By("Verify exporter")
		err = f.VerifyExporter(mysql.ObjectMeta)
		Expect(err).NotTo(HaveOccurred())
		By("Done")
	}

	BeforeEach(func() {
		f = root.Invoke()
		mysql = f.MySQL()
		garbageCASecrets = []*core.Secret{}
		dbName = "mysql"
		skipMessage = ""
	})

	AfterEach(func() {
		// delete resources for current MySQL
		deleteTestResource()

		By("Delete left over workloads if exists any")
		f.CleanWorkloadLeftOvers()
	})

	JustAfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			if mysql.Spec.Replicas == nil {
				mysql.Spec.Replicas = types.Int32P(1)
			}
			f.PrintDebugHelpers(mysql.Name, int(*mysql.Spec.Replicas))
		}
	})

	Describe("Test", func() {
		Context("Exporter", func() {
			Context("Standalone", func() {
				BeforeEach(func() {
					mysql.Spec.RequireSSL = true
				})
				It("Should verify Exporter", verifyExporter)
			})

			Context("Group Replication", func() {
				BeforeEach(func() {
					mysql = f.MySQLGroup()
					mysql.Spec.RequireSSL = true
				})
				It("Should verify Exporter", verifyExporter)

			})

		})

		Context("General", func() {
			Context("with requireSSL true", func() {
				Context("Standalone", func() {
					BeforeEach(func() {
						mysql.Spec.RequireSSL = true
					})
					It("should run successfully", testRequireSSLTrue)
				})

				Context("Group Replication", func() {
					BeforeEach(func() {
						mysql = f.MySQLGroup()
						mysql.Spec.RequireSSL = true
					})
					It("should run successfully", testRequireSSLTrue)
				})

			})

			Context("with requireSSL false", func() {
				Context("Standalone", func() {
					BeforeEach(func() {
						mysql.Spec.RequireSSL = false
					})
					It("should run successfully", testRequireSSLFalse)
				})

				Context("Group Replication", func() {
					BeforeEach(func() {
						mysql = f.MySQLGroup()
						mysql.Spec.RequireSSL = false
					})
					It("should run successfully", testRequireSSLFalse)
				})
			})

		})
	})

})
