package compliance_framework.eks_cluster_require_access_entries_mode

# data.* keys used here come from policies/data.json, which Regal doesn't read, so their
# references carry a line-scoped Regal ignore for the unresolved-reference rule.

test_no_violation_api_mode if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"authentication_mode": "API"}}}
}

test_no_violation_api_and_config_map_mode if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"authentication_mode": "API_AND_CONFIG_MAP"}}}
}

test_violation_config_map_only_mode if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"authentication_mode": "CONFIG_MAP"}}}
}

test_no_violation_custom_allowed_mode if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"authentication_mode": "CONFIG_MAP"}}}
		with data.allowed_authentication_modes as ["CONFIG_MAP"] # regal ignore:unresolved-reference
}
