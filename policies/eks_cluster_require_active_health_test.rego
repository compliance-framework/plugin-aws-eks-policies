package compliance_framework.eks_cluster_require_active_health

# data.* keys used here come from policies/data.json, which Regal doesn't read, so their
# references carry a line-scoped Regal ignore for the unresolved-reference rule.

test_no_violation_when_cluster_active_and_healthy if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"status": "ACTIVE", "health_issue_count": 0}}}
}

test_violation_when_cluster_not_active if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"status": "UPDATING", "health_issue_count": 0}}}
}

test_violation_when_cluster_has_health_issues if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"status": "ACTIVE", "health_issue_count": 2}}}
}

test_two_violations_when_not_active_and_has_health_issues if {
	count(violation) == 2 with input as {"cluster_context": {"current": {"status": "FAILED", "health_issue_count": 1}}}
		with data.approved_cluster_statuses as ["ACTIVE"] # regal ignore:unresolved-reference
}
