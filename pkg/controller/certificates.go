package controller

import (
	"errors"
	"fmt"

	api "kubedb.dev/apimachinery/apis/kubedb/v1alpha1"
	"kubedb.dev/apimachinery/pkg/eventer"

	"github.com/appscode/go/log"
	cm_api "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cm_util "kmodules.xyz/cert-manager-util/certmanager/v1alpha2"
	kutil "kmodules.xyz/client-go"
	core_util "kmodules.xyz/client-go/core/v1"
)

func (c *Controller) manageTLS(mysql *api.MySQL) error {
	if mysql.Spec.TLS.IssuerRef.Kind == cm_api.IssuerKind {
		_, err := c.CertManagerClient.CertmanagerV1alpha2().Issuers(mysql.Namespace).Get(mysql.Spec.TLS.IssuerRef.Name, metav1.GetOptions{})
		if err != nil {
			log.Infoln(err)
			return err
		}
	} else if mysql.Spec.TLS.IssuerRef.Kind == cm_api.ClusterIssuerKind {
		_, err := c.CertManagerClient.CertmanagerV1alpha2().ClusterIssuers().Get(mysql.Spec.TLS.IssuerRef.Name, metav1.GetOptions{})
		if err != nil {
			log.Infoln(err)
			return err
		}
	} else {
		return errors.New("mysql.Spec.TLS.Client.IssuerRef.Kind is not either Issuer or ClusterIssuer")
	}

	if err := c.manageServerCert(mysql); err != nil {
		log.Infoln(err)
		return err
	}

	if err := c.manageClientCert(mysql); err != nil {
		//We're using client certs for e2e-test only at the moment
		log.Infoln(err)
		return err
	}

	if err := c.manageExporterClientCert(mysql); err != nil {
		log.Infoln(err)
		return err
	}
	return nil
}

func (c *Controller) manageServerCert(mysql *api.MySQL) error {
	certVerb, err := c.ensureServerCert(mysql)
	if err != nil {
		return err
	}

	if certVerb == kutil.VerbCreated {
		c.recorder.Event(
			mysql,
			core.EventTypeNormal,
			eventer.EventReasonSuccessful,
			"Successfully created MySQL server certificates",
		)
	} else if certVerb == kutil.VerbPatched {
		c.recorder.Event(
			mysql,
			core.EventTypeNormal,
			eventer.EventReasonSuccessful,
			"Successfully patched MySQL server certificates",
		)
	}
	if certVerb != kutil.VerbUnchanged {
		log.Infoln("server-certificates ", certVerb)
	}

	// wait for certificate secret to be created
	ref := metav1.ObjectMeta{
		Name:      fmt.Sprintf("%s-%s", mysql.Name, api.MySQLServerCertSuffix),
		Namespace: mysql.Namespace,
	}
	if c.secretExists(ref) {
		//set mysql as the owner of the certificate-secret
		if err := c.AddOwnerReferenceToSecret(mysql, ref); err != nil {
			log.Infoln(err)
			return err
		}
	}

	return err
}

func (c *Controller) ensureServerCert(mysql *api.MySQL) (kutil.VerbType, error) {
	var duration, renewBefore *metav1.Duration
	var organization, uriSANs []string
	dnsNames, ipAddresses, err := c.getServiceHosts(mysql.ObjectMeta)
	if mysql.Spec.TLS.Certificate != nil {
		dnsNames = append(dnsNames, mysql.Spec.TLS.Certificate.DNSNames...)
		ipAddresses = append(dnsNames, mysql.Spec.TLS.Certificate.IPAddresses...)
		duration = mysql.Spec.TLS.Certificate.Duration
		renewBefore = mysql.Spec.TLS.Certificate.RenewBefore
		organization = mysql.Spec.TLS.Certificate.Organization
		uriSANs = mysql.Spec.TLS.Certificate.URISANs
	}
	if err != nil {
		return kutil.VerbUnchanged, err
	}
	cert := cm_api.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", mysql.GetName(), api.MySQLServerCertSuffix),
			Namespace: mysql.GetNamespace(),
			Labels:    mysql.GetLabels(),
		},
		TypeMeta: metav1.TypeMeta{
			Kind: cm_api.CertificateKind,
		},
		Spec: cm_api.CertificateSpec{
			CommonName:   c.getServiceURL(mysql.ObjectMeta), //Service name
			Organization: append(organization, "kubedb:server"),
			Duration:     duration, //Default
			RenewBefore:  renewBefore,
			DNSNames:     dnsNames,    // including Service URL, and localhost
			IPAddresses:  ipAddresses, //including 127.0.0.1
			URISANs:      uriSANs,
			SecretName:   fmt.Sprintf("%s-%s", mysql.Name, api.MySQLServerCertSuffix), //Secret where issued certificates will be saved
			IssuerRef: cmmeta.ObjectReference{
				Name: mysql.Spec.TLS.IssuerRef.Name,
				Kind: mysql.Spec.TLS.IssuerRef.Kind,
			},
			IsCA: false,
			Usages: []cm_api.KeyUsage{
				cm_api.UsageDigitalSignature,
				cm_api.UsageKeyEncipherment,
				cm_api.UsageServerAuth,
			},
		},
	}

	ref := metav1.NewControllerRef(mysql, api.SchemeGroupVersion.WithKind(api.ResourceKindMySQL))
	core_util.EnsureOwnerReference(&cert.ObjectMeta, ref)

	_, vt, err := cm_util.CreateOrPatchCertificate(c.CertManagerClient.CertmanagerV1alpha2(), cert.ObjectMeta, func(in *cm_api.Certificate) *cm_api.Certificate {
		in.Spec = cert.Spec
		return in
	})

	return vt, err
}

func (c *Controller) manageClientCert(mysql *api.MySQL) error {
	certVerb, err := c.ensureClientCert(mysql)
	if err != nil {
		return err
	}

	if certVerb == kutil.VerbCreated {
		c.recorder.Event(
			mysql,
			core.EventTypeNormal,
			eventer.EventReasonSuccessful,
			"Successfully created MySQL client-certificates",
		)
	} else if certVerb == kutil.VerbPatched {
		c.recorder.Event(
			mysql,
			core.EventTypeNormal,
			eventer.EventReasonSuccessful,
			"Successfully patched MySQL client-certificates",
		)
	}
	if certVerb != kutil.VerbUnchanged {
		log.Infoln("client-certificates ", certVerb)
	}

	ref := metav1.ObjectMeta{
		Name:      fmt.Sprintf("%s-%s", mysql.Name, api.MySQLClientCertSuffix),
		Namespace: mysql.Namespace,
	}
	if c.secretExists(ref) {
		//set mysql as the owner of the certificate-ref
		if err := c.AddOwnerReferenceToSecret(mysql, ref); err != nil {
			log.Infoln(err)
			return err
		}
	}
	return nil
}

func (c *Controller) ensureClientCert(mysql *api.MySQL) (kutil.VerbType, error) {
	cert := cm_api.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", mysql.GetName(), api.MySQLClientCertSuffix),
			Namespace: mysql.GetNamespace(),
			Labels:    mysql.GetLabels(),
		},
		Spec: cm_api.CertificateSpec{
			CommonName: c.getServiceURL(mysql.ObjectMeta), //Service name
			Duration:   nil,                               //Default
			DNSNames: []string{
				c.getServiceURL(mysql.ObjectMeta),
				"localhost",
			}, //Service name
			IPAddresses: []string{"127.0.0.1"},
			SecretName:  fmt.Sprintf("%s-%s", mysql.Name, api.MySQLClientCertSuffix), //Secret where issued certificates will be saved
			//TODO: Figure out if we need DNS names and IP addresses for client certificates
			IssuerRef: cmmeta.ObjectReference{
				Name: mysql.Spec.TLS.IssuerRef.Name,
				Kind: mysql.Spec.TLS.IssuerRef.Kind,
			},
			IsCA: false,
			Usages: []cm_api.KeyUsage{
				cm_api.UsageDigitalSignature,
				cm_api.UsageKeyEncipherment,
				cm_api.UsageClientAuth,
			},
		},
	}

	ref := metav1.NewControllerRef(mysql, api.SchemeGroupVersion.WithKind(api.ResourceKindMySQL))

	core_util.EnsureOwnerReference(&cert.ObjectMeta, ref)
	_, vt, err := cm_util.CreateOrPatchCertificate(c.CertManagerClient.CertmanagerV1alpha2(), cert.ObjectMeta, func(in *cm_api.Certificate) *cm_api.Certificate {
		in.Spec = cert.Spec
		return in
	})

	return vt, err
}

func (c *Controller) manageExporterClientCert(mysql *api.MySQL) error {
	certVerb, err := c.ensureExporterClientCert(mysql)
	if err != nil {
		return err
	}

	if certVerb == kutil.VerbCreated {
		c.recorder.Event(
			mysql,
			core.EventTypeNormal,
			eventer.EventReasonSuccessful,
			"Successfully created MySQL exporter client-certificates",
		)
	} else if certVerb == kutil.VerbPatched {
		c.recorder.Event(
			mysql,
			core.EventTypeNormal,
			eventer.EventReasonSuccessful,
			"Successfully patched MySQL exporter client-certificates",
		)
	}
	if certVerb != kutil.VerbUnchanged {
		log.Infoln("Exporter client-certificates ", certVerb)
	}

	// wait for certificate secret to be created
	ref := metav1.ObjectMeta{
		Name:      fmt.Sprintf("%s-%s", mysql.Name, api.MySQLExporterClientCertSuffix),
		Namespace: mysql.Namespace,
	}
	if c.secretExists(ref) {
		//set mysql as the owner of the certificate-secret
		if err := c.AddOwnerReferenceToSecret(mysql, ref); err != nil {
			log.Infoln(err)
			return err
		}
	}

	return err
}

func (c *Controller) ensureExporterClientCert(mysql *api.MySQL) (kutil.VerbType, error) {
	cert := cm_api.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", mysql.GetName(), api.MySQLExporterClientCertSuffix),
			Namespace: mysql.GetNamespace(),
			Labels:    mysql.GetLabels(),
		},
		Spec: cm_api.CertificateSpec{
			CommonName: c.getServiceURL(mysql.ObjectMeta), //Service name
			Duration:   nil,                               //Default
			DNSNames: []string{
				c.getServiceURL(mysql.ObjectMeta),
				"localhost",
			}, //Service name
			IPAddresses: []string{"127.0.0.1"},
			//TODO: Figure out if we need DNS names and IP addresses for client certificates
			SecretName: fmt.Sprintf("%s-%s", mysql.Name, api.MySQLExporterClientCertSuffix), //Secret where issued certificates will be saved
			IssuerRef: cmmeta.ObjectReference{
				Name: mysql.Spec.TLS.IssuerRef.Name,
				Kind: mysql.Spec.TLS.IssuerRef.Kind,
			},
			IsCA: false,
			Usages: []cm_api.KeyUsage{
				cm_api.UsageDigitalSignature,
				cm_api.UsageKeyEncipherment,
				cm_api.UsageClientAuth,
			},
		},
	}

	ref := metav1.NewControllerRef(mysql, api.SchemeGroupVersion.WithKind(api.ResourceKindMySQL))

	core_util.EnsureOwnerReference(&cert.ObjectMeta, ref)
	_, vt, err := cm_util.CreateOrPatchCertificate(c.CertManagerClient.CertmanagerV1alpha2(), cert.ObjectMeta, func(in *cm_api.Certificate) *cm_api.Certificate {
		in.Spec = cert.Spec
		return in
	})

	return vt, err
}

func (c *Controller) getServiceURL(mysql metav1.ObjectMeta) string {
	return mysql.Name + "." + mysql.Namespace + ".svc"
}

func (c *Controller) getServiceHosts(objMeta metav1.ObjectMeta) ([]string, []string, error) {
	service, err := c.Client.CoreV1().Services(objMeta.Namespace).Get(objMeta.Name, metav1.GetOptions{})
	if err != nil {
		return []string{}, []string{}, err
	}
	dnsNames := []string{
		c.getServiceURL(objMeta),
		"localhost",
	}
	ipAddresses := []string{"127.0.0.1"}
	serviceIngress := service.Status.LoadBalancer.Ingress
	if len(serviceIngress) > 0 {
		for _, ingresItem := range serviceIngress {
			if ingresItem.Hostname != "" {
				dnsNames = append(dnsNames, ingresItem.Hostname)
			} else if ingresItem.IP != "" {
				ipAddresses = append(ipAddresses, ingresItem.IP)
			}
		}
	}
	return dnsNames, ipAddresses, nil
}

func (c *Controller) secretExists(meta metav1.ObjectMeta) bool {
	_, err := c.Client.CoreV1().Secrets(meta.Namespace).Get(meta.Name, metav1.GetOptions{})
	return err == nil
}

func (c *Controller) AddOwnerReferenceToSecret(mysql *api.MySQL, secretMeta metav1.ObjectMeta) error {
	certificate, err := c.CertManagerClient.CertmanagerV1alpha2().Certificates(secretMeta.Namespace).Get(secretMeta.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	ref1 := core_util.NewOwnerRef(certificate, cm_api.SchemeGroupVersion.WithKind(cm_api.CertificateKind))
	ref2 := metav1.NewControllerRef(mysql, api.SchemeGroupVersion.WithKind(api.ResourceKindMySQL))

	_, _, err = core_util.CreateOrPatchSecret(c.Client, secretMeta, func(in *core.Secret) *core.Secret {
		core_util.EnsureOwnerReference(&in.ObjectMeta, ref1)
		core_util.EnsureOwnerReference(&in.ObjectMeta, ref2)
		return in
	})

	return err
}

func (c *Controller) checkTLSCerts(mysql *api.MySQL) error {
	if _, err := c.Client.CoreV1().Secrets(mysql.Namespace).Get(fmt.Sprintf("%s-%s", mysql.GetName(), api.MySQLClientCertSuffix), metav1.GetOptions{}); err != nil {
		return err
	}

	if _, err := c.Client.CoreV1().Secrets(mysql.Namespace).Get(fmt.Sprintf("%s-%s", mysql.GetName(), api.MySQLServerCertSuffix), metav1.GetOptions{}); err != nil {
		return err
	}

	if _, err := c.Client.CoreV1().Secrets(mysql.Namespace).Get(fmt.Sprintf("%s-%s", mysql.GetName(), api.MySQLExporterClientCertSuffix), metav1.GetOptions{}); err != nil {
		return err
	}
	return nil
}
