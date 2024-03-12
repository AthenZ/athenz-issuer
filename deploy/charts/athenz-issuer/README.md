# athenz-issuer

<!-- AUTO-GENERATED -->

#### **image.registry** ~ `string`

The container registry to pull the controller image from.

#### **image.repository** ~ `string`
> Default value:
> ```yaml
> docker.io/athenz/athenz-issuer
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

