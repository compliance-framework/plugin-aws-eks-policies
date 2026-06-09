package compliance_framework.eks_cluster_require_secrets_encryption

violation[{"id": "eks_secrets_encryption_not_configured"}] if {
	data.require_secrets_encryption
	not cluster_has_default_envelope_encryption
	not secrets_encryption_configured
}

violation[{"id": "eks_customer_managed_kms_key_required"}] if {
	data.require_customer_managed_kms_key
	count(secrets_encryption_customer_key_arns) == 0
}

cluster_has_default_envelope_encryption if {
	version_at_least(cluster_version, data.minimum_version_with_default_secrets_encryption)
}

secrets_encryption_configured if {
	object.get(current, "secrets_encryption_configured", false)
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
