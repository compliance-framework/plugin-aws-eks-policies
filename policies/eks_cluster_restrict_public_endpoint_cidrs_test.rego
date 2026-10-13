package compliance_framework.eks_cluster_restrict_public_endpoint_cidrs

# data.* keys used here come from policies/data.json, which Regal doesn't read, so their
# references carry a line-scoped Regal ignore for the unresolved-reference rule.

test_no_violation_private_endpoint_only if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"endpoint_public_access": false, "endpoint_private_access": true, "public_access_cidrs": []}}}
}

test_violation_when_public_endpoint_not_allowed if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"endpoint_public_access": true, "endpoint_private_access": true, "public_access_cidrs": ["10.0.0.0/8"]}}}
		with data.allow_public_endpoint as false # regal ignore:unresolved-reference
}

test_violation_when_public_endpoint_has_ipv4_world_cidr if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"endpoint_public_access": true, "endpoint_private_access": true, "public_access_cidrs": ["0.0.0.0/0"]}}}
}

test_violation_when_public_endpoint_has_ipv6_world_cidr if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"endpoint_public_access": true, "endpoint_private_access": true, "public_access_cidrs": ["::/0"]}}}
}

test_no_violation_when_broad_cidr_explicitly_allowed if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"endpoint_public_access": true, "endpoint_private_access": true, "public_access_cidrs": ["0.0.0.0/0"]}}}
		with data.allowed_public_endpoint_cidrs as ["0.0.0.0/0"] # regal ignore:unresolved-reference
}

test_violation_when_private_endpoint_required_but_disabled if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"endpoint_public_access": false, "endpoint_private_access": false, "public_access_cidrs": []}}}
		with data.require_private_endpoint_access as true # regal ignore:unresolved-reference
}

test_violation_when_allowlist_configured_and_cidr_not_approved if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"endpoint_public_access": true, "endpoint_private_access": true, "public_access_cidrs": ["203.0.113.0/24"]}}}
		with data.allowed_public_endpoint_cidrs as ["198.51.100.0/24"] # regal ignore:unresolved-reference
}
