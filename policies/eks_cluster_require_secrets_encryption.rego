# METADATA
# title: EKS cluster should protect Kubernetes secrets with envelope encryption
# description: Kubernetes secrets stored in etcd without envelope encryption are at risk if etcd storage is compromised. Envelope encryption adds a KMS-backed protection layer for all secrets at rest.
# custom:
#   controls:
#     - CC6.1
#     - CC6.7
#   schedule: "0 */6 * * *"

package compliance_framework.eks_cluster_require_secrets_encryption

# data.* keys used here come from policies/data.json, which Regal doesn't read, so their
# references carry a line-scoped Regal ignore for the unresolved-reference rule.

violation[{"id": "eks_secrets_encryption_not_configured"}] if {
	data.require_secrets_encryption # regal ignore:unresolved-reference
	not cluster_has_default_envelope_encryption
	not secrets_encryption_configured
}

violation[{"id": "eks_customer_managed_kms_key_required"}] if {
	data.require_customer_managed_kms_key # regal ignore:unresolved-reference
	count(secrets_encryption_customer_key_arns) == 0
}

cluster_has_default_envelope_encryption if {
	version_at_least(cluster_version, data.minimum_version_with_default_secrets_encryption) # regal ignore:unresolved-reference
}

secrets_encryption_configured if {
	object.get(current, "secrets_encryption_configured", false) != false
}

secrets_encryption_customer_key_arns := object.get(current, "secrets_encryption_customer_key_arns", [])

cluster_version := object.get(current, "version", "")

current := object.get(object.get(input, "cluster_context", {}), "current", {})

version_at_least(version, minimum) if {
	version_major(version) > version_major(minimum)
}

version_at_least(version, minimum) if {
	version_major(version) == version_major(minimum)
	version_minor(version) >= version_minor(minimum)
}

version_major(version) := major if {
	parts := split(trim_left(version, "v"), ".")
	count(parts) >= 1
	major := to_number(parts[0])
}

version_minor(version) := minor if {
	parts := split(trim_left(version, "v"), ".")
	count(parts) >= 2
	minor := to_number(parts[1])
}

title := "EKS cluster should protect Kubernetes secrets with envelope encryption"
description := "EKS clusters before Kubernetes 1.28 should configure secrets encryption, while 1.28 or newer clusters are covered by EKS default envelope encryption unless a customer-managed KMS key is required by policy."

risk_templates := [
	{
		"name": "EKS secrets not envelope-encrypted",
		"title": "EKS cluster Kubernetes secrets are not protected by envelope encryption",
		"statement": "Kubernetes secrets stored in etcd are not envelope-encrypted. If etcd storage is compromised, secret values are accessible without an additional encryption barrier.",
		"likelihood_hint": "low",
		"impact_hint": "high",
		"violation_ids": ["eks_secrets_encryption_not_configured"],
		"threat_refs": [{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-312",
			"title": "Cleartext Storage of Sensitive Information",
			"url": "https://cwe.mitre.org/data/definitions/312.html",
		}],
		"remediation": {
			"title": "Enable secrets envelope encryption on the EKS cluster",
			"description": "Enable KMS envelope encryption for Kubernetes secrets. Note: enabling this on an existing cluster re-encrypts all existing secrets.",
			"tasks": [
				{"title": "Create or identify a KMS key for secrets encryption"},
				{"title": "Enable secrets encryption on the cluster specifying the KMS key ARN"},
				{"title": "Verify that secret reads continue to work after encryption is enabled"},
			],
		},
	},
	{
		"name": "EKS secrets not using customer-managed KMS key",
		"title": "EKS cluster secrets envelope encryption does not use a customer-managed KMS key",
		"statement": "Policy requires secrets to be encrypted with a customer-managed KMS key, but no customer-managed key ARN is present in the encryption configuration.",
		"likelihood_hint": "low",
		"impact_hint": "medium",
		"violation_ids": ["eks_customer_managed_kms_key_required"],
		"remediation": {
			"title": "Update secrets encryption to use a customer-managed KMS key",
			"description": "Replace the AWS-managed key with a customer-managed CMK in the cluster's secrets encryption configuration.",
			"tasks": [
				{"title": "Create a customer-managed KMS key with appropriate key policy"},
				{"title": "Update the cluster secrets encryption configuration to reference the CMK ARN"},
				{"title": "Verify key rotation and access policies are configured correctly"},
			],
		},
	},
]
