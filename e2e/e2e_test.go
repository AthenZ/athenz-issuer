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

package e2e_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/AthenZ/athenz-issuer/testutil"

	api "github.com/AthenZ/athenz-issuer/v1"
)

func testClient(t *testing.T) client.WithWatch {
	kubeconfig, ok := os.LookupEnv("KUBECONFIG")
	if !ok {
		t.Fatal("KUBECONFIG environment variable must be set")
	}

	kubeConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
		nil,
	).ClientConfig()
	require.NoError(t, err)

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, cmapi.AddToScheme(scheme))
	require.NoError(t, certificatesv1.AddToScheme(scheme))
	require.NoError(t, api.AddToScheme(scheme))

	controllerClient, err := client.NewWithWatch(kubeConfig, client.Options{Scheme: scheme})
	require.NoError(t, err)

	return controllerClient
}

func TestSimpleCertificate(t *testing.T) {
	ctx := context.Background()

	kubeClient := testClient(t)

	namespace := "test-" + rand.String(20)

	err := kubeClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	})
	require.NoError(t, err)

	serviceAccount := "test-" + rand.String(20)
	err = kubeClient.Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccount,
			Namespace: namespace,
		},
	})
	require.NoError(t, err)

	issuer := testutil.AthenzIssuer("issuer-test",
		testutil.SetAthenzIssuerNamespace(namespace),
	)

	certificate := cmgen.Certificate(
		"test-cert",
		cmgen.SetCertificateNamespace(namespace),
		cmgen.SetCertificateCommonName("test.com"),
		cmgen.SetCertificateSecretName("aaaaaaaa"),
		cmgen.SetCertificateIssuer(v1.ObjectReference{
			Group: issuer.GroupVersionKind().Group,
			Kind:  issuer.Kind,
			Name:  issuer.Name,
		}),
		cmgen.AddCertificateAnnotations(map[string]string{
			"csi.cert-manager.athenz.io/identity": fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/%s", namespace, serviceAccount),
		}),
	)

	err = kubeClient.Create(ctx, issuer)
	require.NoError(t, err)

	err = kubeClient.Create(ctx, certificate)
	require.NoError(t, err)

	if err := wait.PollUntilContextTimeout(ctx, 1*time.Second, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		err := kubeClient.Get(ctx, types.NamespacedName{Name: certificate.Name, Namespace: certificate.Namespace}, certificate)
		if err != nil {
			return false, err
		}

		condition := cmutil.GetCertificateCondition(certificate, cmapi.CertificateConditionReady)

		return condition != nil && condition.Status == v1.ConditionTrue, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSimpleCertificateSigningRequest(t *testing.T) {
	ctx := context.Background()

	kubeClient := testClient(t)

	namespace := "test-" + rand.String(20)
	err := kubeClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	})
	require.NoError(t, err)

	serviceAccount := "test-" + rand.String(20)
	err = kubeClient.Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccount,
			Namespace: namespace,
		},
	})
	require.NoError(t, err)

	csrName := "test-" + rand.String(20)

	clusterIssuer := testutil.AthenzClusterIssuer("cluster-issuer-" + csrName)

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), cryptorand.Reader)
	require.NoError(t, err)

	csrBlob, err := cmgen.CSRWithSigner(privateKey,
		cmgen.SetCSRCommonName("test.com"),
	)
	require.NoError(t, err)

	csr := cmgen.CertificateSigningRequest(
		"csr-"+csrName,
		cmgen.SetCertificateSigningRequestDuration("1h"),
		cmgen.SetCertificateSigningRequestRequest(csrBlob),
		cmgen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{certificatesv1.UsageDigitalSignature}),
		cmgen.SetCertificateSigningRequestSignerName(fmt.Sprintf("athenzclusterissuers.cert-manager.athenz.io/%s", clusterIssuer.Name)),
		cmgen.AddCertificateSigningRequestAnnotations(map[string]string{
			"csi.cert-manager.athenz.io/identity": fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/%s", namespace, serviceAccount),
		}),
	)

	err = kubeClient.Create(ctx, clusterIssuer)
	require.NoError(t, err)

	err = kubeClient.Create(ctx, csr)
	require.NoError(t, err)

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := kubeClient.Get(ctx, types.NamespacedName{Name: csr.Name}, csr); err != nil {
			return err
		}

		nowTime := metav1.NewTime(time.Now())

		csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type:           certificatesv1.CertificateApproved,
			Reason:         "test",
			Message:        "test",
			LastUpdateTime: nowTime,
			Status:         corev1.ConditionTrue,
		})

		return kubeClient.SubResource("approval").Update(ctx, csr)
	})
	require.NoError(t, err)

	if err := wait.PollUntilContextTimeout(ctx, 1*time.Second, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		err := kubeClient.Get(ctx, types.NamespacedName{Name: csr.Name}, csr)
		if err != nil {
			return false, err
		}

		return len(csr.Status.Certificate) > 0, nil
	}); err != nil {
		t.Fatal(err)
	}
}
