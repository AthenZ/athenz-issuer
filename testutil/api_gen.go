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

package testutil

import (
	athenzissuerapi "github.com/AthenZ/athenz-issuer/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/issuer-lib/conditions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
)

type AthenzIssuerModifier func(*athenzissuerapi.AthenzIssuer)

func AthenzIssuer(name string, mods ...AthenzIssuerModifier) *athenzissuerapi.AthenzIssuer {
	c := &athenzissuerapi.AthenzIssuer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AthenzIssuer",
			APIVersion: athenzissuerapi.SchemeGroupVersion.Identifier(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: athenzissuerapi.AthenzCertificateSource{
			ZTSEndpoint:    "https://zts.athenz.io:4443/zts/v1",
			Cloud:          "local",
			Region:         "local",
			ProviderPrefix: "athenz.k8s",
		},
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func AthenzIssuerFrom(cr *athenzissuerapi.AthenzIssuer, mods ...AthenzIssuerModifier) *athenzissuerapi.AthenzIssuer {
	cr = cr.DeepCopy()
	for _, mod := range mods {
		mod(cr)
	}
	return cr
}

func SetAthenzIssuerNamespace(namespace string) AthenzIssuerModifier {
	return func(si *athenzissuerapi.AthenzIssuer) {
		si.Namespace = namespace
	}
}

func SetAthenzIssuerGeneration(generation int64) AthenzIssuerModifier {
	return func(si *athenzissuerapi.AthenzIssuer) {
		si.Generation = generation
	}
}

func SetAthenzIssuerStatusCondition(
	clock clock.PassiveClock,
	conditionType cmapi.IssuerConditionType,
	status cmmeta.ConditionStatus,
	reason, message string,
) AthenzIssuerModifier {
	return func(si *athenzissuerapi.AthenzIssuer) {
		conditions.SetIssuerStatusCondition(
			clock,
			si.Status.Conditions,
			&si.Status.Conditions,
			si.Generation,
			conditionType,
			status,
			reason,
			message,
		)
	}
}

type AthenzClusterIssuerModifier func(*athenzissuerapi.AthenzClusterIssuer)

func AthenzClusterIssuer(name string, mods ...AthenzClusterIssuerModifier) *athenzissuerapi.AthenzClusterIssuer {
	c := &athenzissuerapi.AthenzClusterIssuer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AthenzClusterIssuer",
			APIVersion: athenzissuerapi.SchemeGroupVersion.Identifier(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: athenzissuerapi.AthenzCertificateSource{
			ZTSEndpoint:    "https://zts.athenz.io:4443/zts/v1",
			Cloud:          "local",
			Region:         "local",
			ProviderPrefix: "athenz.k8s",
		},
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func AthenzClusterIssuerFrom(cr *athenzissuerapi.AthenzClusterIssuer, mods ...AthenzClusterIssuerModifier) *athenzissuerapi.AthenzClusterIssuer {
	cr = cr.DeepCopy()
	for _, mod := range mods {
		mod(cr)
	}
	return cr
}

func SetAthenzClusterIssuerGeneration(generation int64) AthenzClusterIssuerModifier {
	return func(si *athenzissuerapi.AthenzClusterIssuer) {
		si.Generation = generation
	}
}

func SetAthenzClusterIssuerStatusCondition(
	clock clock.PassiveClock,
	conditionType cmapi.IssuerConditionType,
	status cmmeta.ConditionStatus,
	reason, message string,
) AthenzClusterIssuerModifier {
	return func(si *athenzissuerapi.AthenzClusterIssuer) {
		conditions.SetIssuerStatusCondition(
			clock,
			si.Status.Conditions,
			&si.Status.Conditions,
			si.Generation,
			conditionType,
			status,
			reason,
			message,
		)
	}
}
