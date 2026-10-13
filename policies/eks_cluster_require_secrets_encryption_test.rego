package compliance_framework.eks_cluster_require_secrets_encryption

# data.* keys used here come from policies/data.json, which Regal doesn't read, so their
# references carry a line-scoped Regal ignore for the unresolved-reference rule.

test_no_violation_for_eks_128_or_newer_without_explicit_config if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"version": "1.28", "secrets_encryption_configured": false, "secrets_encryption_customer_key_arns": []}}}
}

test_violation_for_older_cluster_without_secrets_encryption_config if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"version": "1.27", "secrets_encryption_configured": false, "secrets_encryption_customer_key_arns": []}}}
}

test_no_violation_for_older_cluster_with_secrets_encryption_config if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"version": "1.27", "secrets_encryption_configured": true, "secrets_encryption_customer_key_arns": ["arn:aws:kms:eu-west-2:123456789012:key/abc"]}}}
}

test_violation_when_customer_managed_key_required_but_missing if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"version": "1.30", "secrets_encryption_configured": false, "secrets_encryption_customer_key_arns": []}}}
		with data.require_customer_managed_kms_key as true # regal ignore:unresolved-reference
}

test_no_violation_when_customer_managed_key_required_and_present if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"version": "1.30", "secrets_encryption_configured": true, "secrets_encryption_customer_key_arns": ["arn:aws:kms:eu-west-2:123456789012:key/abc"]}}}
		with data.require_customer_managed_kms_key as true # regal ignore:unresolved-reference
}

test_no_violation_when_secrets_encryption_not_required if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"version": "1.27", "secrets_encryption_configured": false, "secrets_encryption_customer_key_arns": []}}}
		with data.require_secrets_encryption as false # regal ignore:unresolved-reference
}
