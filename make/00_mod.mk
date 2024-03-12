# Copyright The Athenz Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

repo_name := github.com/AthenZ/athenz-issuer

kind_cluster_name := athenz-issuer
kind_cluster_config := $(bin_dir)/scratch/kind_cluster.yaml

oci_platforms := linux/amd64,linux/arm64

build_names := manager

go_manager_main_dir := ./cmd
go_manager_mod_dir := .
go_manager_ldflags := -X $(repo_name)/internal/version.AppVersion=$(VERSION) -X $(repo_name)/internal/version.GitCommit=$(GITCOMMIT)
oci_manager_base_image_flavor := static
oci_manager_image_name := docker.io/athenz/athenz-issuer
oci_manager_image_tag := $(VERSION)
oci_manager_image_name_development := athenz.local/athenz-issuer

deploy_name := athenz-issuer
deploy_namespace := athenz-issuer-system

api_docs_outfile := docs/v1/v1.md
api_docs_package := $(repo_name)/v1
api_docs_branch := main

helm_chart_source_dir := deploy/charts/athenz-issuer
helm_chart_name := athenz-issuer
helm_chart_version := $(VERSION)
helm_labels_template_name := athenz-issuer.labels
helm_docs_use_helm_tool := 1
helm_generate_schema := 1 
helm_verify_values := 1 

define helm_values_mutation_function
$(YQ) \
	'( .image.repository = "$(oci_manager_image_name)" ) | \
	( .image.tag = "$(oci_manager_image_tag)" )' \
	$1 --inplace
endef
