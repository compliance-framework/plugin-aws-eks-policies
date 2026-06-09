package compliance_framework.eks_cluster_restrict_bootstrap_creator_admin

violation[{"id": "eks_bootstrap_creator_admin_enabled"}] if {
	not data.allow_bootstrap_creator_admin
	bootstrap_creator_admin_enabled
}

bootstrap_creator_admin_enabled if {
	object.get(object.get(object.get(input, "cluster_context", {}), "current", {}), "bootstrap_creator_admin_permissions", false)
}

title := "EKS bootstrap cluster creator admin permissions should be disabled"
description := "EKS bootstrap cluster creator admin permissions should be disabled unless explicitly allowed by policy."
