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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	athenzissuerapi "github.com/AthenZ/athenz-issuer/v1"
	"github.com/AthenZ/athenz/clients/go/zts"
)

type ztsRequest struct {
	path      string
	userAgent string
	info      zts.InstanceRegisterInformation
}

type fakeZTS struct {
	t        *testing.T
	server   *httptest.Server
	endpoint string
	cert     string

	mu       sync.Mutex
	requests []ztsRequest
}

func newFakeZTS(t *testing.T, cert string) *fakeZTS {
	f := &fakeZTS{t: t, cert: cert}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	f.endpoint = f.server.URL + "/zts/v1"
	return f
}

func (f *fakeZTS) handle(w http.ResponseWriter, r *http.Request) {
	var info zts.InstanceRegisterInformation
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		f.t.Errorf("decode ZTS request: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, ztsRequest{path: r.URL.Path, userAgent: r.Header.Get("User-Agent"), info: info})
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(zts.InstanceIdentity{
		Provider:        info.Provider,
		Name:            zts.ServiceName(string(info.Domain) + "." + string(info.Service)),
		InstanceId:      info.X509CertInstanceId,
		X509Certificate: f.cert,
	})
}

func (f *fakeZTS) recorded() []ztsRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ztsRequest(nil), f.requests...)
}

// fakeSAToken encodes the audience into the token so tests can see which issuer's endpoint it was minted for.
func fakeSAToken(_ context.Context, namespace, serviceAccount, audience string) (string, *corev1.ServiceAccount, error) {
	return "token-aud=" + audience, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccount,
			Namespace: namespace,
			UID:       types.UID("uid-" + namespace + "-" + serviceAccount),
		},
	}, nil
}

func newTestCR(t *testing.T, namespace, serviceAccount string) signer.CertificateRequestObject {
	t.Helper()
	spiffe := fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/%s", namespace, serviceAccount)
	uri, err := url.Parse(spiffe)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{uri}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return signer.CertificateRequestObjectFromCertificateRequest(&cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "cr-" + serviceAccount,
			Namespace:         namespace,
			CreationTimestamp: metav1.NewTime(time.Now()),
			Annotations:       map[string]string{"csi.cert-manager.athenz.io/identity": spiffe},
		},
		Spec: cmapi.CertificateRequestSpec{
			Request: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		},
	})
}

type signCase struct {
	issuer    v1alpha1.Issuer
	zts       *fakeZTS
	namespace string
	sa        string
	domain    string
	service   string
	provider  string
	cloud     string
}

func newTwoIssuerCases(t *testing.T) []signCase {
	ztsA := newFakeZTS(t, "cert-from-zts-a")
	ztsB := newFakeZTS(t, "cert-from-zts-b")
	return []signCase{
		{
			issuer: &athenzissuerapi.AthenzIssuer{
				ObjectMeta: metav1.ObjectMeta{Name: "issuer-a", Namespace: "team-a"},
				Spec: athenzissuerapi.AthenzCertificateSource{
					ZTSEndpoint: ztsA.endpoint, Cloud: "aws", Region: "us-east-1", ProviderPrefix: "athenz.prov-a",
				},
			},
			zts: ztsA, namespace: "team-a", sa: "dom.a.svc-a", domain: "dom.a", service: "svc-a",
			provider: "athenz.prov-a.aws-us-east-1", cloud: "aws",
		},
		{
			issuer: &athenzissuerapi.AthenzClusterIssuer{
				ObjectMeta: metav1.ObjectMeta{Name: "issuer-b"},
				Spec: athenzissuerapi.AthenzCertificateSource{
					ZTSEndpoint: ztsB.endpoint, Cloud: "gcp", Region: "us-west1", ProviderPrefix: "athenz.prov-b",
				},
			},
			zts: ztsB, namespace: "team-b", sa: "dom.b.svc-b", domain: "dom.b", service: "svc-b",
			provider: "athenz.prov-b.gcp-us-west1", cloud: "gcp",
		},
	}
}

func checkSignResult(t *testing.T, c signCase, bundle signer.PEMBundle, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("Sign via %s: %v", c.issuer.GetName(), err)
		return
	}
	if got, want := string(bundle.ChainPEM), c.zts.cert; got != want {
		t.Errorf("Sign via %s returned %q, want %q", c.issuer.GetName(), got, want)
	}
}

func checkZTSRequest(t *testing.T, c signCase, r ztsRequest) {
	t.Helper()
	var att K8SAttestationData
	if err := json.Unmarshal([]byte(r.info.AttestationData), &att); err != nil {
		t.Fatalf("attestation data: %v", err)
	}
	checks := []struct{ field, got, want string }{
		{"path", r.path, "/zts/v1/instance"},
		{"User-Agent", r.userAgent, "athenz-issuer"},
		{"provider", string(r.info.Provider), c.provider},
		{"cloud", string(r.info.Cloud), c.cloud},
		{"domain", string(r.info.Domain), c.domain},
		{"service", string(r.info.Service), c.service},
		{"namespace", string(r.info.Namespace), c.namespace},
		{"instance id", string(r.info.X509CertInstanceId), "uid-" + c.namespace + "-" + c.sa},
		{"token audience", att.IdentityToken, "token-aud=" + c.zts.endpoint},
	}
	for _, ch := range checks {
		if ch.got != ch.want {
			t.Errorf("%s: ZTS request %s = %q, want %q", c.issuer.GetName(), ch.field, ch.got, ch.want)
		}
	}
}

func TestSignUsesReferencedIssuer(t *testing.T) {
	cases := newTwoIssuerCases(t)
	s := &Signer{MaxRetryDuration: time.Minute, saToken: fakeSAToken}
	ctx := context.Background()

	// Check every issuer first so the last one checked differs from the first one signed.
	for _, c := range cases {
		if err := s.Check(ctx, c.issuer); err != nil {
			t.Fatalf("Check(%s): %v", c.issuer.GetName(), err)
		}
	}

	for _, c := range cases {
		bundle, err := s.Sign(ctx, newTestCR(t, c.namespace, c.sa), c.issuer)
		checkSignResult(t, c, bundle, err)
	}

	for _, c := range cases {
		reqs := c.zts.recorded()
		if len(reqs) != 1 {
			t.Fatalf("%s: ZTS got %d requests, want 1", c.issuer.GetName(), len(reqs))
		}
		checkZTSRequest(t, c, reqs[0])
	}
}

func TestSignLocalCloudSkipsZTS(t *testing.T) {
	fake := newFakeZTS(t, "unused")
	s := &Signer{MaxRetryDuration: time.Minute, saToken: fakeSAToken}
	issuer := &athenzissuerapi.AthenzIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "local", Namespace: "ns"},
		Spec:       athenzissuerapi.AthenzCertificateSource{ZTSEndpoint: fake.endpoint, Cloud: "local", Region: "r", ProviderPrefix: "p"},
	}

	bundle, err := s.Sign(context.Background(), newTestCR(t, "ns", "dom.svc"), issuer)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(bundle.ChainPEM); block == nil || block.Type != "CERTIFICATE" {
		t.Errorf("local Sign returned %q, want a PEM certificate", bundle.ChainPEM)
	}
	if n := len(fake.recorded()); n != 0 {
		t.Errorf("local Sign sent %d ZTS requests, want 0", n)
	}
}

func TestCheckRejectsForeignIssuer(t *testing.T) {
	s := &Signer{}
	if err := s.Check(context.Background(), nil); err == nil {
		t.Error("Check accepted a non-Athenz issuer")
	}
}

// Run with -race: Check and Sign share one Signer across all reconcilers.
func TestConcurrentCheckAndSign(t *testing.T) {
	cases := newTwoIssuerCases(t)
	s := &Signer{MaxRetryDuration: time.Minute, saToken: fakeSAToken}
	ctx := context.Background()

	crs := make([]signer.CertificateRequestObject, len(cases))
	for i, c := range cases {
		crs[i] = newTestCR(t, c.namespace, c.sa)
	}

	const workers, iterations = 8, 10
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := range iterations {
				if err := s.Check(ctx, cases[(w+i)%len(cases)].issuer); err != nil {
					t.Errorf("Check: %v", err)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := range iterations {
				n := (w + i) % len(cases)
				c := cases[n]
				bundle, err := s.Sign(ctx, crs[n], c.issuer)
				checkSignResult(t, c, bundle, err)
			}
		}()
	}
	wg.Wait()

	total := 0
	for _, c := range cases {
		reqs := c.zts.recorded()
		total += len(reqs)
		for _, r := range reqs {
			checkZTSRequest(t, c, r)
		}
	}
	if want := workers * iterations; total != want {
		t.Errorf("ZTS got %d requests in total, want %d", total, want)
	}
}
