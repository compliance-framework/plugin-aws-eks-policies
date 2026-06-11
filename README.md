# AWS EKS cluster policies

Standalone OPA/Rego policy bundle for EKS cluster evidence emitted by the `plugin-aws-eks` collector.

## Input schema

Each policy evaluates one EKS cluster at a time using:

- `input.cluster`
- `input.cluster_context`

Current cluster context includes cluster status, EKS health issue count, control-plane log types, endpoint public/private access configuration, public endpoint CIDRs, secrets encryption summary, access configuration, and summarized related managed add-ons.

## Current coverage

This bundle currently checks cluster-level EKS posture:

- cluster is active and has no unresolved EKS health issues
- required control-plane log types are enabled
- public Kubernetes API endpoint CIDRs are constrained
- secrets encryption posture is acceptable for the cluster version and policy baseline
- authentication mode supports approved EKS access entry modes
- bootstrap cluster creator admin permissions are disabled unless allowed
- policy-defined required managed add-ons are installed and active

Node group and add-on resource policies live in separate bundles.

## Policy data

Default baselines live in `policies/data.json` and can be overridden by agent-supplied policy data.

| Key | Type | Default | Policies that read it |
|-----|------|---------|----------------------|
| `approved_cluster_statuses` | `array<string>` | `["ACTIVE"]` | `eks_cluster_require_active_health` |
| `required_control_plane_log_types` | `array<string>` | `["audit", "authenticator"]` | `eks_cluster_require_control_plane_audit_logging` |
| `allow_public_endpoint` | `boolean` | `true` | `eks_cluster_restrict_public_endpoint_cidrs` |
| `require_private_endpoint_access` | `boolean` | `false` | `eks_cluster_restrict_public_endpoint_cidrs` |
| `broad_public_endpoint_cidrs` | `array<string>` | `["0.0.0.0/0", "::/0"]` | `eks_cluster_restrict_public_endpoint_cidrs` |
| `allowed_public_endpoint_cidrs` | `array<string>` | `[]` | `eks_cluster_restrict_public_endpoint_cidrs` |
| `require_secrets_encryption` | `boolean` | `true` | `eks_cluster_require_secrets_encryption` |
| `minimum_version_with_default_secrets_encryption` | `string` | `"1.28"` | `eks_cluster_require_secrets_encryption` |
| `require_customer_managed_kms_key` | `boolean` | `false` | `eks_cluster_require_secrets_encryption` |
| `allowed_authentication_modes` | `array<string>` | `["API", "API_AND_CONFIG_MAP"]` | `eks_cluster_require_access_entries_mode` |
| `allow_bootstrap_creator_admin` | `boolean` | `false` | `eks_cluster_restrict_bootstrap_creator_admin` |
| `required_addons` | `array<string>` | `[]` | `eks_cluster_require_managed_addons` |

## Testing

Run local checks with:

```shell
opa check policies
opa test policies
```

Or use the Makefile wrappers:

```shell
make validate
make test
```

## Bundling

Build the distributable bundle with:

```shell
make build
```

This writes `dist/bundle.tar.gz`.
