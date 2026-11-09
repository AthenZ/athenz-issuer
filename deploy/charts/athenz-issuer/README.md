# athenz-issuer

<!-- AUTO-GENERATED -->

#### **image.registry** ~ `string`

The container registry to pull the controller image from.

#### **image.repository** ~ `string`
> Default value:
> ```yaml
> docker.io/athenz/athenz-cert-manager-issuer
> ```

The container image for the athenz-issuer controller.

#### **image.tag** ~ `string`

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion is used.

#### **image.digest** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Target athenz-issuer digest. Override any tag, if set.  
For example:

```yaml
manager: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20
```


```yaml
manager: sha256:...
```
#### **image.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

Kubernetes imagePullPolicy on Deployment
#### **imagePullSecrets** ~ `array`
> Default value:
> ```yaml
> []
> ```

Optional secrets used for pulling the athenz-issuer container image  
For example:

```yaml
imagePullSecrets:
  - name: "image-pull-secret"
```
#### **commonLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Labels to apply to all resources
#### **fullnameOverride** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

Override the full name
#### **nameOverride** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

Override the name
#### **serviceAccount.create** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Specifies whether a service account should be created.
#### **serviceAccount.name** ~ `string`

The name of the service account to use.  
If not set and create is true, a name is generated using the fullname template.

#### **serviceAccount.annotations** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Optional additional annotations to add to the controller's Service Account.

#### **serviceAccount.labels** ~ `object`

Optional additional labels to add to the controller's Service Account.

#### **serviceAccount.automountServiceAccountToken** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Automount API credentials for a Service Account.
#### **resources.limits.cpu** ~ `string`
> Default value:
> ```yaml
> 500m
> ```
#### **resources.limits.memory** ~ `string`
> Default value:
> ```yaml
> 128Mi
> ```
#### **resources.requests.cpu** ~ `string`
> Default value:
> ```yaml
> 100m
> ```
#### **resources.requests.memory** ~ `string`
> Default value:
> ```yaml
> 64Mi
> ```
#### **replicaCount** ~ `number`
> Default value:
> ```yaml
> 1
> ```
#### **maxConcurrentReconciles** ~ `number`

Maximum number of CertificateRequests reconciled in parallel (--max-concurrent-reconciles). Must be an integer >= 1. Issuers are always reconciled by one worker.  
If unset, the controller default of 1 is used.

#### **kubeApiQps** ~ `number`

Client-side QPS limit for Kubernetes API requests (--kube-api-qps). Applies to every API client the controller uses, including the ServiceAccount get and TokenRequest made for each signed request. Each client enforces the limit separately. If unset, zero or negative, client-side rate limiting is disabled and API Priority and Fairness applies.

#### **kubeApiBurst** ~ `number`

Client-side burst limit for Kubernetes API requests (--kube-api-burst), applied to the same clients as kubeApiQps. Must be an integer. Only used when kubeApiQps is positive; if unset or not positive it defaults to max(10, 2*kubeApiQps).

#### **hostAliases** ~ `array`

Optional /etc/hosts entries to inject into the controller pod (Pod.spec.hostAliases).

#### **crds.enabled** ~ `bool`
> Default value:
> ```yaml
> true
> ```
#### **crds.keep** ~ `bool`
> Default value:
> ```yaml
> true
> ```

