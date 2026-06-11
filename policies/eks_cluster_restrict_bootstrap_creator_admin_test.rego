package compliance_framework.eks_cluster_restrict_bootstrap_creator_admin

test_no_violation_when_bootstrap_admin_disabled if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"bootstrap_creator_admin_permissions": false}}}
}

test_violation_when_bootstrap_admin_enabled if {
	count(violation) == 1 with input as {"cluster_context": {"current": {"bootstrap_creator_admin_permissions": true}}}
}

test_no_violation_when_bootstrap_admin_allowed_by_policy_data if {
	count(violation) == 0 with input as {"cluster_context": {"current": {"bootstrap_creator_admin_permissions": true}}}
		with data.allow_bootstrap_creator_admin as true
}
