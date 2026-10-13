package compliance_framework.eks_cluster_require_control_plane_audit_logging

# data.* keys used here come from policies/data.json, which Regal doesn't read, so their
# references carry a line-scoped Regal ignore for the unresolved-reference rule.

test_no_violation_when_required_logs_enabled if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"enabled_control_plane_log_types": ["audit", "authenticator"]}}}
}

test_violation_when_audit_log_missing if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"enabled_control_plane_log_types": ["authenticator"]}}}
}

test_no_violation_when_required_logs_overridden if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"enabled_control_plane_log_types": ["api"]}}}
		with data.required_control_plane_log_types as ["api"] # regal ignore:unresolved-reference
}

test_two_violations_when_all_required_log_types_absent if {
	count(violation) == 2 with input as {"cluster_context": {"current": {"enabled_control_plane_log_types": []}}}
}

test_skip_when_required_logs_not_configured if {
	skip_reason == "required EKS control plane log types are not configured" with data.required_control_plane_log_types as [] # regal ignore:unresolved-reference
}
