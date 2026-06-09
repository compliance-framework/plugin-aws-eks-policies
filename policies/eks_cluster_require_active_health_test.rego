package compliance_framework.eks_cluster_require_active_health

test_no_violation_when_cluster_active_and_healthy if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"status": "ACTIVE", "health_issue_count": 0}}}
}

test_violation_when_cluster_not_active if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"status": "UPDATING", "health_issue_count": 0}}}
}

test_violation_when_cluster_has_health_issues if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"status": "ACTIVE", "health_issue_count": 2}}}
}
