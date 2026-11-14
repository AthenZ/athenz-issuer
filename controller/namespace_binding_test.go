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
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	issuerutil "github.com/AthenZ/athenz-issuer/internal"
	athenzissuerapi "github.com/AthenZ/athenz-issuer/v1"
)

func testNamespace(name, domainAnnotation string) *corev1.Namespace {
	return testNamespaceWith(name, domainAnnotation, "")
}

// testNamespaceWith builds a Namespace with optional athenz.io/domain annotation and label.
func testNamespaceWith(name, domainAnnotation, domainLabel string) *corev1.Namespace {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if domainAnnotation != "" {
		ns.Annotations = map[string]string{AthenzDomainKey: domainAnnotation}
	}
	if domainLabel != "" {
		ns.Labels = map[string]string{AthenzDomainKey: domainLabel}
	}
	return ns
}

func TestCheckNamespaceDomain(t *testing.T) {
	exceptions, err := ParseNamespaceDomainExceptions([]string{"shared-tools=platform.tools", "istio-system=example.k8s"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		namespaces []*corev1.Namespace
		namespace  string
		domain     string
		wantErr    string // "" = allowed
		mismatch   bool
	}{
		{name: "name maps to domain", namespaces: []*corev1.Namespace{testNamespace("app-backend", "")},
			namespace: "app-backend", domain: "app.backend"},
		{name: "name with escaped dashes", namespaces: []*corev1.Namespace{testNamespace("sports-user--services--nonprod", "")},
			namespace: "sports-user--services--nonprod", domain: "sports.user-services-nonprod"},
		{name: "name maps to another domain", namespaces: []*corev1.Namespace{testNamespace("tenant-a", "")},
			namespace: "tenant-a", domain: "other", wantErr: `its name maps to domain "tenant.a"`, mismatch: true},
		{name: "annotation equals domain", namespaces: []*corev1.Namespace{testNamespace("finance-k8s-nonprod", "finance.k8s.nonprod")},
			namespace: "finance-k8s-nonprod", domain: "finance.k8s.nonprod"},
		{name: "annotation consistent with name but another domain requested",
			namespaces: []*corev1.Namespace{testNamespace("tenant-a", "tenant.a")},
			namespace:  "tenant-a", domain: "other", wantErr: "annotated athenz.io/domain=tenant.a", mismatch: true},
		{name: "several namespaces share one annotated domain: first", namespaces: []*corev1.Namespace{testNamespace("payments-prod", "payments.prod")},
			namespace: "payments-prod", domain: "payments.prod"},
		{name: "several namespaces share one annotated domain: name differs", namespaces: []*corev1.Namespace{testNamespace("payments-batch", "payments.prod")},
			namespace: "payments-batch", domain: "payments.prod"},
		{name: "several namespaces share one annotated domain: unrelated name", namespaces: []*corev1.Namespace{testNamespace("team-x-tools", "payments.prod")},
			namespace: "team-x-tools", domain: "payments.prod"},
		{name: "name match passes even when annotated with another domain", namespaces: []*corev1.Namespace{testNamespace("app-backend", "payments.prod")},
			namespace: "app-backend", domain: "app.backend"},
		{name: "annotated namespace refuses a domain matching neither name nor annotation", namespaces: []*corev1.Namespace{testNamespace("app-backend", "payments.prod")},
			namespace: "app-backend", domain: "other", wantErr: "annotated athenz.io/domain=payments.prod", mismatch: true},
		{name: "label only: equals domain", namespaces: []*corev1.Namespace{testNamespaceWith("omega-monitoring", "", "omega.team")},
			namespace: "omega-monitoring", domain: "omega.team"},
		{name: "label only: another domain", namespaces: []*corev1.Namespace{testNamespaceWith("omega-monitoring", "", "omega.team")},
			namespace: "omega-monitoring", domain: "other", wantErr: "is labeled athenz.io/domain=omega.team", mismatch: true},
		{name: "name match passes even when labeled with another domain", namespaces: []*corev1.Namespace{testNamespaceWith("app-backend", "", "omega.team")},
			namespace: "app-backend", domain: "app.backend"},
		{name: "annotation wins over the label", namespaces: []*corev1.Namespace{testNamespaceWith("ns-a", "payments.prod", "omega.team")},
			namespace: "ns-a", domain: "payments.prod"},
		{name: "annotation wins over the label: label domain refused", namespaces: []*corev1.Namespace{testNamespaceWith("ns-a", "payments.prod", "omega.team")},
			namespace: "ns-a", domain: "omega.team", wantErr: "annotated athenz.io/domain=payments.prod", mismatch: true},
		{name: "annotated platform namespace (ambient ztunnel)", namespaces: []*corev1.Namespace{testNamespace("istio-system", "athenz.k8s.nonprod")},
			namespace: "istio-system", domain: "athenz.k8s.nonprod"},
		{name: "unannotated platform namespace", namespaces: []*corev1.Namespace{testNamespace("cert-manager", "")},
			namespace: "cert-manager", domain: "example.k8s", wantErr: `its name maps to domain "cert.manager" and it has no athenz.io/domain annotation or label`, mismatch: true},
		{name: "exception, no API call needed", namespace: "shared-tools", domain: "platform.tools"},
		{name: "exception for another domain does not apply", namespaces: []*corev1.Namespace{testNamespace("shared-tools", "")},
			namespace: "shared-tools", domain: "other", wantErr: "may not hold", mismatch: true},
		{name: "name match needs no namespace lookup", namespace: "gone", domain: "gone"},
		{name: "namespace not found", namespace: "gone", domain: "other", wantErr: "failed to get namespace gone"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := make([]runtime.Object, len(tt.namespaces))
			for i, ns := range tt.namespaces {
				objs[i] = ns
			}
			kube := fake.NewClientset(objs...)
			err := checkNamespaceDomain(context.Background(), kube, exceptions, tt.namespace, tt.domain)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkNamespaceDomain = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("checkNamespaceDomain = %v, want it to contain %q", err, tt.wantErr)
			}
			var m *namespaceDomainMismatchError
			if got := errors.As(err, &m); got != tt.mismatch {
				t.Errorf("error is a mismatch = %v, want %v", got, tt.mismatch)
			}
		})
	}
}

func TestParseNamespaceDomainBinding(t *testing.T) {
	for _, v := range []string{"off", "warn", "enforce"} {
		if b, err := ParseNamespaceDomainBinding(v); err != nil || string(b) != v {
			t.Errorf("ParseNamespaceDomainBinding(%q) = %q, %v", v, b, err)
		}
	}
	for _, v := range []string{"", "Enforce", "on"} {
		if _, err := ParseNamespaceDomainBinding(v); err == nil {
			t.Errorf("ParseNamespaceDomainBinding(%q) accepted an invalid value", v)
		}
	}
}

func TestParseNamespaceDomainExceptions(t *testing.T) {
	e, err := ParseNamespaceDomainExceptions([]string{"a=x.y", " a = z ", "b=w"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := e.String(), "a=x.y,a=z,b=w"; got != want {
		t.Errorf("exceptions = %q, want %q", got, want)
	}
	for _, bad := range []string{"a", "=x", "a=", ""} {
		if _, err := ParseNamespaceDomainExceptions([]string{bad}); err == nil {
			t.Errorf("ParseNamespaceDomainExceptions(%q) accepted an invalid entry", bad)
		}
	}
}

// signWithBinding signs a request for namespace/serviceAccount and reports the result,
// whether a ServiceAccount token was requested and how many ZTS calls were made, then the error.
func signWithBinding(t *testing.T, binding NamespaceDomainBinding, requesters []string, ns *corev1.Namespace, namespace, serviceAccount, crNamespace string) (bool, int, error) {
	t.Helper()
	zts := newFakeZTS(t, "cert")
	kube := newFakeKube(testSA(namespace, serviceAccount))
	if ns != nil {
		if _, err := kube.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	kube.ClearActions()
	cnr, err := ParseCrossNamespaceRequesters(requesters)
	if err != nil {
		t.Fatal(err)
	}
	s := &Signer{MaxRetryDuration: time.Minute, kubeClient: kube, NamespaceDomainBinding: binding, CrossNamespaceRequesters: cnr}
	issuer := &athenzissuerapi.AthenzClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "issuer"},
		Spec:       athenzissuerapi.AthenzCertificateSource{ZTSEndpoint: zts.endpoint, Cloud: "aws", Region: "us-east-1", ProviderPrefix: "p"},
	}
	cr := newTestCRWithAnnotations(t, namespace, serviceAccount, nil)
	if crNamespace != namespace {
		// istio-csr creates the CR in its own namespace for a workload elsewhere
		cr = withCRNamespace(t, cr, crNamespace)
	}
	_, err = s.Sign(context.Background(), cr, issuer)
	tokenRequested := false
	for _, a := range kube.Actions() {
		if a.GetSubresource() == "token" {
			tokenRequested = true
		}
	}
	return tokenRequested, len(zts.recorded()), err
}

func withCRNamespace(t *testing.T, cr signer.CertificateRequestObject, namespace string) signer.CertificateRequestObject {
	t.Helper()
	obj, ok := cr.(interface{ GetObjectMeta() metav1.Object })
	if !ok {
		t.Skip("CertificateRequestObject does not expose its metadata")
	}
	obj.GetObjectMeta().SetNamespace(namespace)
	return cr
}

func TestSignNamespaceDomainBinding(t *testing.T) {
	tests := []struct {
		name          string
		binding       NamespaceDomainBinding
		ns            *corev1.Namespace
		namespace, sa string
		crNamespace   string
		requesters    []string
		wantErr       string
		wantPermanent bool
	}{
		{name: "enforce: SA of another domain in an annotated namespace is refused", binding: BindingEnforce,
			ns: testNamespace("tenant-a", "tenant.a"), namespace: "tenant-a", sa: "other.svc",
			wantErr: "may not hold identities", wantPermanent: true},
		{name: "enforce: SA of another domain in an unannotated namespace is refused", binding: BindingEnforce,
			ns: testNamespace("tenant-a", ""), namespace: "tenant-a", sa: "other.svc",
			wantErr: "may not hold identities", wantPermanent: true},
		{name: "enforce: workload in its domain namespace signs", binding: BindingEnforce,
			ns: testNamespace("app-frontend", ""), namespace: "app-frontend", sa: "app.frontend.curl"},
		{name: "enforce: ambient workload SVID with CR in a listed requester namespace signs", binding: BindingEnforce,
			ns: testNamespace("app-frontend", ""), namespace: "app-frontend", sa: "app.frontend.curl",
			crNamespace: "cert-manager", requesters: []string{"cert-manager"}},
		{name: "enforce: CR in an unlisted namespace naming another namespace is refused", binding: BindingEnforce,
			ns: testNamespace("app-frontend", ""), namespace: "app-frontend", sa: "app.frontend.curl",
			crNamespace: "tenant-a", requesters: []string{"cert-manager"},
			wantErr: `CertificateRequest in namespace "tenant-a" may not ask for an identity in namespace "app-frontend"`, wantPermanent: true},
		{name: "enforce: CR in cert-manager is refused when no requester is listed", binding: BindingEnforce,
			ns: testNamespace("app-frontend", ""), namespace: "app-frontend", sa: "app.frontend.curl",
			crNamespace: "cert-manager", wantErr: "may not ask for an identity", wantPermanent: true},
		{name: "enforce: a listed requester still needs the target namespace to hold the domain", binding: BindingEnforce,
			ns: testNamespace("tenant-a", "tenant.a"), namespace: "tenant-a", sa: "other.svc",
			crNamespace: "cert-manager", requesters: []string{"cert-manager"},
			wantErr: "may not hold identities", wantPermanent: true},
		{name: "warn: CR in an unlisted namespace naming another namespace still signs", binding: BindingWarn,
			ns: testNamespace("app-frontend", ""), namespace: "app-frontend", sa: "app.frontend.curl", crNamespace: "tenant-a"},
		{name: "warn: requester and domain mismatch both still sign", binding: BindingWarn,
			ns: testNamespace("tenant-a", "tenant.a"), namespace: "tenant-a", sa: "other.svc", crNamespace: "tenant-b"},
		{name: "off: CR in an unlisted namespace naming another namespace signs", binding: BindingOff,
			ns: testNamespace("app-frontend", ""), namespace: "app-frontend", sa: "app.frontend.curl", crNamespace: "tenant-a"},
		{name: "enforce: SA in a second namespace annotated with the same domain signs", binding: BindingEnforce,
			ns: testNamespace("payments-batch", "payments.prod"), namespace: "payments-batch", sa: "payments.prod.worker"},
		{name: "enforce: ambient waypoint signs", binding: BindingEnforce,
			ns: testNamespace("app-backend", "app.backend"), namespace: "app-backend", sa: "app.backend.waypoint"},
		{name: "enforce: annotated istio-system ztunnel signs", binding: BindingEnforce,
			ns: testNamespace("istio-system", "example.k8s"), namespace: "istio-system", sa: "example.k8s.ztunnel"},
		{name: "enforce: unannotated istio-system ztunnel is refused", binding: BindingEnforce,
			ns: testNamespace("istio-system", ""), namespace: "istio-system", sa: "example.k8s.ztunnel",
			wantErr: "may not hold identities", wantPermanent: true},
		{name: "enforce: namespace read failure is retryable", binding: BindingEnforce,
			namespace: "tenant-a", sa: "other.svc", wantErr: "failed to get namespace"},
		{name: "warn: SA of another domain still signs", binding: BindingWarn,
			ns: testNamespace("tenant-a", "tenant.a"), namespace: "tenant-a", sa: "other.svc"},
		{name: "warn: namespace read failure still signs", binding: BindingWarn,
			namespace: "tenant-a", sa: "other.svc"},
		{name: "off: SA of another domain signs", binding: BindingOff,
			ns: testNamespace("tenant-a", "tenant.a"), namespace: "tenant-a", sa: "other.svc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crNS := tt.crNamespace
			if crNS == "" {
				crNS = tt.namespace
			}
			tokenRequested, ztsCalls, err := signWithBinding(t, tt.binding, tt.requesters, tt.ns, tt.namespace, tt.sa, crNS)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Sign = %v, want success", err)
				}
				if !tokenRequested || ztsCalls != 1 {
					t.Errorf("token requested = %v, ZTS calls = %d, want true and 1", tokenRequested, ztsCalls)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Sign = %v, want it to contain %q", err, tt.wantErr)
			}
			if got := errors.As(err, new(signer.PermanentError)); got != tt.wantPermanent {
				t.Errorf("permanent = %v, want %v", got, tt.wantPermanent)
			}
			if tokenRequested {
				t.Error("a ServiceAccount token was requested for a refused request")
			}
			if ztsCalls != 0 {
				t.Errorf("ZTS got %d requests for a refused request, want 0", ztsCalls)
			}
		})
	}
}

// The off binding must not read Namespaces, so the issuer keeps working without the new RBAC.
func TestSignBindingOffMakesNoNamespaceCalls(t *testing.T) {
	c := newTwoIssuerCases(t)[0]
	kube := newFakeKube(testSA(c.namespace, c.sa))
	var namespaceCalls int
	kube.PrependReactor("*", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		namespaceCalls++
		return false, nil, nil
	})
	s := &Signer{MaxRetryDuration: time.Minute, kubeClient: kube}
	if _, err := s.Sign(context.Background(), newTestCR(t, c.namespace, c.sa), c.issuer); err != nil {
		t.Fatal(err)
	}
	if namespaceCalls != 0 {
		t.Errorf("binding off made %d namespace calls, want 0", namespaceCalls)
	}
}

func TestCheckRequesterNamespace(t *testing.T) {
	requesters, err := ParseCrossNamespaceRequesters([]string{"cert-manager", " kube-addons "})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		requester, namespace string
		wantErr              bool
	}{
		{requester: "app-frontend", namespace: "app-frontend"},
		{requester: "cert-manager", namespace: "app-frontend"},
		{requester: "kube-addons", namespace: "app-frontend"},
		{requester: "tenant-a", namespace: "app-frontend", wantErr: true},
		// A cluster-scoped CertificateSigningRequest has no namespace.
		{requester: "", namespace: "app-frontend", wantErr: true},
	}
	for _, tt := range tests {
		err := checkRequesterNamespace(requesters, tt.requester, tt.namespace)
		if (err != nil) != tt.wantErr {
			t.Errorf("checkRequesterNamespace(%q, %q) = %v, want error %v", tt.requester, tt.namespace, err, tt.wantErr)
		}
		if err != nil && !isBindingMismatch(err) {
			t.Errorf("checkRequesterNamespace(%q, %q) = %v, want a binding mismatch", tt.requester, tt.namespace, err)
		}
	}
}

func TestParseCrossNamespaceRequesters(t *testing.T) {
	for _, bad := range [][]string{{""}, {"  "}, {"cert-manager", ""}, {"Cert-Manager"}, {"kube.addons"}, {"ns/x"}} {
		if _, err := ParseCrossNamespaceRequesters(bad); err == nil {
			t.Errorf("ParseCrossNamespaceRequesters(%q) accepted an invalid value", bad)
		}
	}
	r, err := ParseCrossNamespaceRequesters([]string{"kube-addons", "cert-manager", "cert-manager"})
	if err != nil || r.String() != "cert-manager,kube-addons" {
		t.Errorf("ParseCrossNamespaceRequesters = %q, %v", r.String(), err)
	}
}

// In warn, both checks run, so the log carries every reason enforce would refuse.
func TestBindingWarnReportsBothReasons(t *testing.T) {
	kube := newFakeKube()
	if _, err := kube.CoreV1().Namespaces().Create(context.Background(), testNamespace("tenant-a", "tenant.a"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	err := errors.Join(checkRequesterNamespace(nil, "tenant-b", "tenant-a"),
		checkNamespaceDomain(context.Background(), kube, nil, "tenant-a", "other"))
	if !isBindingMismatch(err) {
		t.Fatalf("joined error %v is not a binding mismatch", err)
	}
	for _, want := range []string{"may not ask for an identity", "may not hold identities"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error %q does not contain %q", err, want)
		}
	}
}

// A Kubernetes CertificateSigningRequest is cluster-scoped: under enforce it is refused before
// any token is requested.
func TestSignEnforceRefusesClusterScopedRequest(t *testing.T) {
	tokenRequested, ztsCalls, err := signWithBinding(t, BindingEnforce, []string{"cert-manager"},
		testNamespace("app-frontend", ""), "app-frontend", "app.frontend.curl", "")
	if err == nil || !strings.Contains(err.Error(), "cluster-scoped request") {
		t.Fatalf("Sign = %v, want a cluster-scoped refusal", err)
	}
	if !errors.As(err, new(signer.PermanentError)) {
		t.Errorf("Sign = %v, want a permanent error", err)
	}
	if tokenRequested || ztsCalls != 0 {
		t.Errorf("token requested = %v, ZTS calls = %d, want false and 0", tokenRequested, ztsCalls)
	}
}

// A CSR with a second SPIFFE URI is refused before any token is requested, whatever the
// binding: only one identity may be checked and signed.
func TestSignRefusesMultipleSpiffeURIs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var uris []*url.URL
	for _, s := range []string{"spiffe://cluster.local/ns/app-frontend/sa/app.frontend.curl", "spiffe://cluster.local/ns/tenant-a/sa/other.svc"} {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, u)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: uris}, key)
	if err != nil {
		t.Fatal(err)
	}
	cr := signer.CertificateRequestObjectFromCertificateRequest(&cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "cr-multi", Namespace: "app-frontend", CreationTimestamp: metav1.NewTime(time.Now())},
		Spec:       cmapi.CertificateRequestSpec{Request: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})},
	})
	for _, binding := range []NamespaceDomainBinding{BindingOff, BindingWarn, BindingEnforce} {
		zts := newFakeZTS(t, "cert")
		kube := newFakeKube(testSA("app-frontend", "app.frontend.curl"))
		s := &Signer{MaxRetryDuration: time.Minute, kubeClient: kube, NamespaceDomainBinding: binding}
		issuer := &athenzissuerapi.AthenzClusterIssuer{
			ObjectMeta: metav1.ObjectMeta{Name: "issuer"},
			Spec:       athenzissuerapi.AthenzCertificateSource{ZTSEndpoint: zts.endpoint, Cloud: "aws", Region: "us-east-1", ProviderPrefix: "p"},
		}
		_, err := s.Sign(context.Background(), cr, issuer)
		if !errors.Is(err, issuerutil.ErrMultipleSpiffeURIs) || !errors.As(err, new(signer.PermanentError)) {
			t.Fatalf("binding %s: Sign = %v, want a permanent multiple-SPIFFE-URI error", binding, err)
		}
		for _, a := range kube.Actions() {
			if a.GetSubresource() == "token" {
				t.Errorf("binding %s: a ServiceAccount token was requested", binding)
			}
		}
		if n := len(zts.recorded()); n != 0 {
			t.Errorf("binding %s: ZTS got %d requests, want 0", binding, n)
		}
	}
}
