# baseline-rules
A package to handle the reading and processing of baseline rules (corporate policies).
A baseline-rule file is a YAML file containing a list of Rule objects, and each object has the following (optional) properties.

|Property   |Description     |Type  |Default|
|-----------|----------------|------|-------|
|name       |Rule name. Must match the requirements of [K8s DNS Subdomain Names](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names)|string|`no-name`|
|description|Rule description|string|`''`|
|action     |Whether to allow or deny the specified connections. Either `allow` or `deny`|string|`allow`|
|from       |Connections source. Either a [K8s set-based requirement](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#set-based-requirement) or a [CIDR](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.21/#ipblock-v1-networking-k8s-io)|string|`null` (all sources)|
|to         |Connections destination. Either a [K8s set-based requirement](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#set-based-requirement) or a [CIDR](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.21/#ipblock-v1-networking-k8s-io)|string|`null` (all destinations)|
|from_ns    |Source Namespaces. a [K8s set-based requirement](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#set-based-requirement)|string|`null` (all source namespaces)|
|to_ns    |Destination Namespaces. a [K8s set-based requirement](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#set-based-requirement)|string|`null` (all destination namespaces)|
|protocol   |Connections protocol. Must be [supported by K8s](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.21/#networkpolicyport-v1-networking-k8s-io).|string|`null` (all protocols)|
|port_min   |Minimal connections port. Must be in range [1, 65535]|int|`null` (no minimal port)|
|port_max   |Maximal connections port. Must be in range [1, 65535]|int|`null` (no maximal port)|

Examples are available in the [examples directory](https://github.com/np-guard/baseline-rules/tree/master/examples).
