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

Default baselines live in `policies/data.json` and can be overridden by agent-supplied policy data. Current settings cover approved cluster status, required log types, endpoint access expectations, EKS default secrets encryption version handling, customer-managed KMS requirements, allowed authentication modes, bootstrap creator admin permission allowance, and required managed add-ons.

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
