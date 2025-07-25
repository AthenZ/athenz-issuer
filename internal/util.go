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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
)

const (
	SpiffeUriPattern = `^spiffe://[^/]+/ns/([^/]+)/sa/([^/]+)$`
)

var (
	regex = regexp.MustCompile(SpiffeUriPattern)
)

// ExtractNamespaceAndServiceAccountFromSpiffeURI Given a spiffe uri in the format of spiffe://<trust-domain>/ns/<ns>/sa/<sa>
// write a function in golang to return the namespace and service account name
// e.g spiffe://cluster.local/ns/default/sa/athenz.example => return default, athenz.example
func ExtractNamespaceAndServiceAccountFromSpiffeURI(spiffeURI string) (string, string, error) {

	// Find the matches in the input string
	matches := regex.FindStringSubmatch(spiffeURI)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid SPIFFE URI format")
	}
	// Extract the namespace and service account name from the matches
	namespace := matches[1]
	serviceAccount := matches[2]

	return namespace, serviceAccount, nil
}

func ExtractSpiffeURIFromAnnotations(annotations map[string]string) (string, error) {
	spiffeURI, ok := annotations["csi.cert-manager.athenz.io/identity"]
	if !ok {
		return "", fmt.Errorf("spiffe uri not found in annotations")
	}
	return spiffeURI, nil
}

// ExtractDomainServiceFromServiceAccount extract domain and service from the service account name
// e.g. athenz.prod.api -> domain: athenz.prod, service: api
func ExtractDomainServiceFromServiceAccount(saName string) (string, string) {
	domain := ""
	service := saName
	if idx := strings.LastIndex(saName, "."); idx != -1 {
		domain = saName[:idx]
		service = saName[idx+1:]
	}
	return domain, service
}

func ExtractSpiffeURIFromCSR(csrBytes []byte) (string, error) {
	// Decode the PEM encoded CSR
	block, rest := pem.Decode(csrBytes)
	if block == nil {
		return "", fmt.Errorf("no PEM block found in input")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return "", fmt.Errorf("not a certificate request PEM block")
	}

	if len(rest) > 0 {
		return "", fmt.Errorf("unexpected data found after PEM block")
	}

	// Parse the CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse CSR: %v", err)
	}

	for _, uri := range csr.URIs {
		if strings.HasPrefix(uri.String(), "spiffe://") {
			return uri.String(), nil
		}
	}

	return "", fmt.Errorf("unable to extract SPIFFE URI from CSR")
}
