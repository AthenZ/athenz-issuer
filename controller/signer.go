/*
Copyright The Athenz Authors.

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

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"

	issuerutil "github.com/AthenZ/athenz-issuer/internal"
	athenzissuerapi "github.com/AthenZ/athenz-issuer/v1"
	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
)

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=patch

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=sign,resourceNames=athenzissuers.cert-manager.athenz.io/*;athenzclusterissuers.cert-manager.athenz.io/*

// +kubebuilder:rbac:groups=cert-manager.athenz.io,resources=athenzissuers;athenzclusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.athenz.io,resources=athenzissuers/status;athenzclusterissuers/status,verbs=patch

// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// +kubebuilder:rbac:groups=core,resources=serviceaccounts;serviceaccounts/token,verbs=create;get

type Signer struct {
	ztsEndpoint    string
	ztsClient      zts.ZTSClient
	cloud          string
	region         string
	providerPrefix string
}

type K8SAttestationData struct {
	IdentityToken string `json:"identityToken,omitempty"` //the service account token obtained from the api server
}

func (s Signer) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	return (&controllers.CombinedController{
		IssuerTypes:        []v1alpha1.Issuer{&athenzissuerapi.AthenzIssuer{}},
		ClusterIssuerTypes: []v1alpha1.Issuer{&athenzissuerapi.AthenzClusterIssuer{}},

		FieldOwner:       "athenzissuer.cert-manager.athenz.io",
		MaxRetryDuration: 1 * time.Minute,

		Sign:          s.Sign,
		Check:         s.Check,
		EventRecorder: mgr.GetEventRecorderFor("athenzissuer.cert-manager.athenz.io"),
	}).SetupWithManager(ctx, mgr)
}

func (s *Signer) Check(ctx context.Context, issuerObject v1alpha1.Issuer) error {
	switch t := issuerObject.(type) {
	case *athenzissuerapi.AthenzIssuer:
		s.ztsEndpoint = t.Spec.ZTSEndpoint
		s.region = t.Spec.Region
		s.cloud = t.Spec.Cloud
		s.providerPrefix = t.Spec.ProviderPrefix
	case *athenzissuerapi.AthenzClusterIssuer:
		s.ztsEndpoint = t.Spec.ZTSEndpoint
		s.region = t.Spec.Region
		s.cloud = t.Spec.Cloud
		s.providerPrefix = t.Spec.ProviderPrefix
	default:
		return fmt.Errorf("not an issuer type: %t", t)
	}
	// create zts client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{},
		Proxy:           http.ProxyFromEnvironment,
	}

	s.ztsClient = zts.NewClient(s.ztsEndpoint, tr)
	s.ztsClient.AddCredentials("User-Agent", "athenz-issuer")
	return nil
}

func (s *Signer) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObject v1alpha1.Issuer) (signer.PEMBundle, error) {

	// load client certificate request
	clientCRTTemplate, _, csrBytes, err := cr.GetRequest()
	if err != nil {
		return signer.PEMBundle{}, err
	}

	// Get the service account name from cr
	spiffeURI, err := issuerutil.ExtractSpiffeURIFromAnnotations(cr.GetAnnotations())
	if err != nil {
		fmt.Printf("Unable to extract spiffe uri from annotations, err: %v\n", err)
		spiffeURI, err = issuerutil.ExtractSpiffeURIFromCSR(csrBytes)
	}

	fmt.Printf("spiffeURI=%s\n", spiffeURI)
	spiffeNS, spiffeSA, err := issuerutil.ExtractNamespaceAndServiceAccountFromSpiffeURI(spiffeURI)

	// use the token in zts api call
	saTok, err := getServiceAccountTokenFromAPIServer(spiffeNS, ctx, spiffeSA, s)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	athenzDomain, athenzService := issuerutil.ExtractDomainServiceFromServiceAccount(spiffeSA)
	athenzProvider := fmt.Sprintf("%s.%s-%s", s.providerPrefix, s.cloud, s.region)

	data, err := json.Marshal(&K8SAttestationData{
		IdentityToken: string(saTok),
	})

	fmt.Printf("athenzDomain=%s athenzService=%s athenzProvider=%s\n", athenzDomain, athenzService, athenzProvider)

	if s.cloud == "local" {
		// generate random ca private key
		caPrivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return signer.PEMBundle{}, err
		}

		caCRT := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Athenz Inc."},
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour * 24 * 180),

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		// create client certificate from template and CA public key
		clientCRTRaw, err := x509.CreateCertificate(rand.Reader, clientCRTTemplate, caCRT, clientCRTTemplate.PublicKey, caPrivateKey)
		if err != nil {
			panic(err)
		}

		clientCrt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
		fmt.Printf("clientCrt=%s\n", clientCrt)
		return signer.PEMBundle{
			ChainPEM: clientCrt,
		}, nil
	} else {
		identity, _, err := s.ztsClient.PostInstanceRegisterInformation(&zts.InstanceRegisterInformation{
			Domain:          zts.DomainName(athenzDomain),
			Service:         zts.SimpleName(athenzService),
			Provider:        zts.ServiceName(athenzProvider),
			AttestationData: string(data),
			Csr:             string(csrBytes),
			Cloud:           zts.SimpleName(s.cloud),
			Namespace:       zts.SimpleName(spiffeNS),
		})
		if err != nil {
			fmt.Printf("Unable to do PostInstanceRegisterInformation, err: %v\n", err)
			return signer.PEMBundle{}, err
		}

		if identity != nil {
			return signer.PEMBundle{
				ChainPEM: []byte(identity.X509Certificate),
			}, nil
		} else {
			fmt.Println("identity is nil")
			return signer.PEMBundle{}, nil
		}
	}
}

func getServiceAccountTokenFromAPIServer(namespaceName string, ctx context.Context, spiffeSA string, signerObj *Signer) (string, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return "", fmt.Errorf("failed to get in cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", fmt.Errorf("failed to get clientset: %w", err)
	}

	sa, err := clientset.CoreV1().ServiceAccounts(namespaceName).Get(ctx, spiffeSA, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get service account: %w", err)
	}

	tr := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: []string{signerObj.ztsEndpoint},
		},
	}
	tokenReq, err := clientset.CoreV1().ServiceAccounts(namespaceName).CreateToken(ctx, sa.Name, tr, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	return tokenReq.Status.Token, nil
}
