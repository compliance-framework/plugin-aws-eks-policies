package compliance_framework.eks_cluster_require_managed_addons

# data.* keys used here come from policies/data.json, which Regal doesn't read, so their
# references carry a line-scoped Regal ignore for the unresolved-reference rule.

test_skip_when_required_addons_not_configured if {
	skip_reason == "required EKS managed add-ons are not configured" with data.required_addons as [] # regal ignore:unresolved-reference
}

test_no_violation_when_required_addons_active if {
	count(violation) == 0 with input as {"cluster_context": {"current": {
		"related_managed_addon_names": ["vpc-cni", "coredns"],
		"active_related_managed_addon_names": ["vpc-cni", "coredns"],
	}}}
		with data.required_addons as ["vpc-cni", "coredns"] # regal ignore:unresolved-reference
}

test_violation_when_required_addon_missing if {
	count(violation) == 1 with input as {"cluster_context": {"current": {
		"related_managed_addon_names": ["vpc-cni"],
		"active_related_managed_addon_names": ["vpc-cni"],
	}}}
		with data.required_addons as ["vpc-cni", "coredns"] # regal ignore:unresolved-reference
}

test_violation_when_required_addon_installed_but_not_active if {
	count(violation) == 1 with input as {"cluster_context": {"current": {
		"related_managed_addon_names": ["vpc-cni", "coredns"],
		"active_related_managed_addon_names": ["vpc-cni"],
	}}}
		with data.required_addons as ["vpc-cni", "coredns"] # regal ignore:unresolved-reference
}
