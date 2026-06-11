# METADATA
# title: EKS bootstrap cluster creator admin permissions should be disabled
# description: Enabling bootstrap cluster creator admin permissions grants the cluster creator implicit cluster-admin access outside the EKS access entries model, making it harder to audit and revoke.
# custom:
#   controls:
#     - CC6.1
#     - CC6.2
#   schedule: "0 */6 * * *"

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

risk_templates := [{
	"name":            "EKS bootstrap creator admin permissions enabled",
	"title":           "EKS cluster has bootstrap creator admin permissions enabled",
	"statement":       "Bootstrap cluster creator admin permissions are enabled, granting implicit cluster-admin access to the creator principal outside the auditable EKS access entries model.",
	"likelihood_hint": "medium",
	"impact_hint":     "high",
	"violation_ids":   ["eks_bootstrap_creator_admin_enabled"],
	"remediation": {
		"title":       "Disable bootstrap creator admin permissions and use explicit access entries",
		"description": "Create an explicit EKS access entry for the cluster creator with the required permissions, then disable the bootstrap creator admin flag. This ensures all access is managed through the auditable access entries API.",
		"tasks": [
			{"title": "Create an explicit EKS access entry for the current cluster creator principal"},
			{"title": "Verify the explicit entry grants the required cluster access"},
			{"title": "Disable bootstrap_cluster_creator_admin_permissions in the cluster configuration"}
		]
	}
}]
