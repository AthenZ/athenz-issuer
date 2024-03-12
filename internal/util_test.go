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
	"testing"
)

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