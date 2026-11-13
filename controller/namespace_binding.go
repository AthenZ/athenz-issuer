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
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	issuerutil "github.com/AthenZ/athenz-issuer/internal"
)

// AthenzDomainKey is the Namespace annotation, and failing that the Namespace label, set by
// cluster admins, that names the Athenz domain whose identities the namespace may hold.
// csi-driver-athenz reads the same key in the same order.
const AthenzDomainKey = "athenz.io/domain"

// NamespaceDomainBinding controls whether Sign checks that the namespace in the CSR's SPIFFE
// URI may hold identities of the Athenz domain the URI names.
type NamespaceDomainBinding string

const (
	// BindingOff skips the check. It is the zero value.
	BindingOff NamespaceDomainBinding = "off"
	// BindingWarn runs the check and logs a mismatch, but still signs.
	BindingWarn NamespaceDomainBinding = "warn"
	// BindingEnforce refuses a mismatching request before any ServiceAccount token is requested.
	BindingEnforce NamespaceDomainBinding = "enforce"
)

// ParseNamespaceDomainBinding parses the --namespace-domain-binding flag value.
func ParseNamespaceDomainBinding(s string) (NamespaceDomainBinding, error) {
	switch b := NamespaceDomainBinding(s); b {
	case BindingOff, BindingWarn, BindingEnforce:
		return b, nil
	}
	return "", fmt.Errorf("invalid namespace domain binding %q: must be one of off, warn, enforce", s)
}

// NamespaceDomainExceptions lists, per namespace, extra Athenz domains whose identities the
// namespace may hold even though neither its annotation nor its name names them.
type NamespaceDomainExceptions map[string]map[string]struct{}

// ParseNamespaceDomainExceptions parses repeated --namespace-domain-exception values of the
// form <namespace>=<domain>.
func ParseNamespaceDomainExceptions(entries []string) (NamespaceDomainExceptions, error) {
	exceptions := NamespaceDomainExceptions{}
	for _, entry := range entries {
		namespace, domain, ok := strings.Cut(entry, "=")
		namespace, domain = strings.TrimSpace(namespace), strings.TrimSpace(domain)
		if !ok || namespace == "" || domain == "" {
			return nil, fmt.Errorf("invalid namespace domain exception %q: must be <namespace>=<domain>", entry)
		}
		if exceptions[namespace] == nil {
			exceptions[namespace] = map[string]struct{}{}
		}
		exceptions[namespace][domain] = struct{}{}
	}
	return exceptions, nil
}

func (e NamespaceDomainExceptions) allows(namespace, domain string) bool {
	_, ok := e[namespace][domain]
	return ok
}

// String lists the exceptions in a stable order, for logging.
func (e NamespaceDomainExceptions) String() string {
	var entries []string
	for namespace, domains := range e {
		for domain := range domains {
			entries = append(entries, namespace+"="+domain)
		}
	}
	sort.Strings(entries)
	return strings.Join(entries, ",")
}

// namespaceDomainMismatch reports that a namespace may not hold identities of a domain. It is
// distinct from a failure to read the Namespace, which is worth retrying.
type namespaceDomainMismatch struct {
	namespace, domain, reason string
}

func (m *namespaceDomainMismatch) Error() string {
	return fmt.Sprintf("namespace %q may not hold identities of Athenz domain %q: %s", m.namespace, m.domain, m.reason)
}

// checkNamespaceDomain returns nil when namespace may hold identities of domain, a
// *namespaceDomainMismatch when it may not, and any other error when the Namespace could not
// be read.
//
// A namespace whose name is the dashed form of domain (sports-user--services for
// sports.user-services) passes without an API call, as do the admin exceptions. Otherwise the
// namespace's authoritative domain is its athenz.io/domain annotation, else its
// athenz.io/domain label, and it must equal domain. Only cluster admins can edit a Namespace.
func checkNamespaceDomain(ctx context.Context, kube kubernetes.Interface, exceptions NamespaceDomainExceptions, namespace, domain string) error {
	if issuerutil.NamespaceToDomain(namespace) == domain || exceptions.allows(namespace, domain) {
		return nil
	}
	ns, err := kube.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get namespace %s to check its Athenz domain: %w", namespace, err)
	}
	if annotated := ns.GetAnnotations()[AthenzDomainKey]; annotated != "" {
		if annotated == domain {
			return nil
		}
		return &namespaceDomainMismatch{namespace, domain,
			fmt.Sprintf("its name does not map to the domain and it is annotated %s=%s", AthenzDomainKey, annotated)}
	}
	if labeled := ns.GetLabels()[AthenzDomainKey]; labeled != "" {
		if labeled == domain {
			return nil
		}
		return &namespaceDomainMismatch{namespace, domain,
			fmt.Sprintf("its name does not map to the domain and it is labeled %s=%s", AthenzDomainKey, labeled)}
	}
	return &namespaceDomainMismatch{namespace, domain,
		fmt.Sprintf("its name maps to domain %q and it has no %s annotation or label", issuerutil.NamespaceToDomain(namespace), AthenzDomainKey)}
}
