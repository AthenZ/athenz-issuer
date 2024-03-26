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
package issuerutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"testing"
)

type CertReqDetails struct {
	CommonName string
	Country    string
	Province   string
	Locality   string
	Org        string
	OrgUnit    string
	IpList     []string
	HostList   []string
	EmailList  []string
	URIs       []*url.URL
}

func TestExtractNamespaceAndServiceAccountFromSpiffeURI(t *testing.T) {
	testCases := []struct {
		input              string
		expectedNamespace  string
		expectedSA         string
		expectError        bool
	}{
		// Test cases with valid input
		{
			input:              "spiffe://cluster.local/ns/default/sa/my.example",
			expectedNamespace:  "default",
			expectedSA:         "my.example",
			expectError:        false,
		},
		{
			input:              "spiffe://example.com/ns/test/sa/serviceaccount",
			expectedNamespace:  "test",
			expectedSA:         "serviceaccount",
			expectError:        false,
		},
		// Test cases with invalid input
		{
			input:              "invalid-spiffe-uri",
			expectedNamespace:  "",
			expectedSA:         "",
			expectError:        true,
		},
		{
			input:              "spiffe://example.com/invalid",
			expectedNamespace:  "",
			expectedSA:         "",
			expectError:        true,
		},
	}

	for _, tc := range testCases {
		namespace, sa, err := ExtractNamespaceAndServiceAccountFromSpiffeURI(tc.input)

		if tc.expectError && err == nil {
			t.Errorf("Expected an error for input: %s", tc.input)
		}

		if !tc.expectError && err != nil {
			t.Errorf("Unexpected error for input: %s - %v", tc.input, err)
		}

		if namespace != tc.expectedNamespace {
			t.Errorf("Expected namespace '%s', but got '%s' for input: %s", tc.expectedNamespace, namespace, tc.input)
		}

		if sa != tc.expectedSA {
			t.Errorf("Expected service account '%s', but got '%s' for input: %s", tc.expectedSA, sa, tc.input)
		}
	}
}

func TestExtractSpiffeURIFromAnnotations(t *testing.T) {
	testCases := []struct {
		input              map[string]string
		expectedSpiffeURI  string
		expectError        bool
	}{
		// Test cases with valid input
		{
			input:              map[string]string{"csi.cert-manager.athenz.io/identity": "spiffe://cluster.local/ns/default/sa/my.example"},
			expectedSpiffeURI:  "spiffe://cluster.local/ns/default/sa/my.example",
			expectError:        false,
		},
		{
			input:              map[string]string{"csi.cert-manager.athenz.io/identity": "spiffe://example.com/ns/test/sa/serviceaccount"},
			expectedSpiffeURI:  "spiffe://example.com/ns/test/sa/serviceaccount",
			expectError:        false,
		},
		// Test cases with invalid input
		{
			input:              map[string]string{"csi.cert-manager.athenz.io/identity": "invalid-spiffe-uri"},
			expectedSpiffeURI:  "invalid-spiffe-uri",
			expectError:        false,
		},
		{
			input:              map[string]string{},
			expectedSpiffeURI:  "",
			expectError:        true,
		},
	}

	for _, tc := range testCases {
		spiffeURI, err := ExtractSpiffeURIFromAnnotations(tc.input)

		if tc.expectError && err == nil {
			t.Errorf("Expected an error for input: %v", tc.input)
		}

		if !tc.expectError && err != nil {
			t.Errorf("Unexpected error for input: %v - %v", tc.input, err)
		}

		if spiffeURI != tc.expectedSpiffeURI {
			t.Errorf("Expected spiffe uri '%s', but got '%s' for input: %v", tc.expectedSpiffeURI, spiffeURI, tc.input)
		}
	}
}

func TestExtractSpiffeURIFromCSR(t *testing.T) {
	testCases := []struct {
		input              []byte
		expectedSpiffeURI  string
		expectError        bool
	}{
		{
			input:              []byte(generateX509CSR(genKey(), defaultCSRDetails())),
			expectedSpiffeURI:  "spiffe://cluster.local/ns/default/sa/athenz.api",
			expectError:        false,
		},
		{
			input:              make([]byte, 0),
			expectedSpiffeURI:  "",
			expectError:        true,
		},
	}

	for _, tc := range testCases {
		spiffeURI, err := ExtractSpiffeURIFromCSR(tc.input)

		if tc.expectError && err == nil {
			t.Errorf("Expected an error for input: %v", tc.input)
		}

		if !tc.expectError && err != nil {
			t.Errorf("Unexpected error for input: %v - %v", tc.input, err)
		}

		if spiffeURI != tc.expectedSpiffeURI {
			t.Errorf("Expected spiffe uri '%s', but got '%s' for input: %v", tc.expectedSpiffeURI, spiffeURI, tc.input)
		}
	}
}

func generateX509CSR(key *ecdsa.PrivateKey, csrDetails CertReqDetails) (string) {
	subj := pkix.Name{CommonName: csrDetails.CommonName}
	if csrDetails.Country != "" {
		subj.Country = []string{csrDetails.Country}
	}
	if csrDetails.Province != "" {
		subj.Province = []string{csrDetails.Province}
	}
	if csrDetails.Locality != "" {
		subj.Locality = []string{csrDetails.Locality}
	}
	if csrDetails.Org != "" {
		subj.Organization = []string{csrDetails.Org}
	}
	if csrDetails.OrgUnit != "" {
		subj.OrganizationalUnit = []string{csrDetails.OrgUnit}
	}
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	if len(csrDetails.IpList) != 0 {
		template.IPAddresses = make([]net.IP, 0)
		for _, ip := range csrDetails.IpList {
			template.IPAddresses = append(template.IPAddresses, net.ParseIP(ip))
		}
	}
	template.DNSNames = csrDetails.HostList
	template.EmailAddresses = csrDetails.EmailList
	template.URIs = csrDetails.URIs
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return ""
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, block)
	if err != nil {
		return ""
	}
	return buf.String()
}

func genKey() (*ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key
}

func defaultCSRDetails() CertReqDetails {
	uris := []*url.URL{}
	uri, _ := url.Parse("spiffe://cluster.local/ns/default/sa/athenz.api")
	return CertReqDetails {
		CommonName: "athenz.api",
		Country:    "US",
		Org:        "Athenz",
		URIs: append(uris, uri),
	}
}