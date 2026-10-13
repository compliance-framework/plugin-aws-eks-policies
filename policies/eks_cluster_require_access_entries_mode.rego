# METADATA
# title: EKS cluster should use an approved authentication mode
# description: EKS access entry API provides improved RBAC management. Disallowed authentication modes may expose legacy access paths that bypass IAM controls.
# custom:
#   controls:
#     - CC6.1
#     - CC6.3
#   schedule: "0 */6 * * *"

package compliance_framework.eks_cluster_require_access_entries_mode

# data.* keys used here come from policies/data.json, which Regal doesn't read, so their
# references carry a line-scoped Regal ignore for the unresolved-reference rule.

violation[{"authentication_mode": authentication_mode, "id": "eks_authentication_mode_not_allowed"}] if {
	not allowed_authentication_mode
}

allowed_authentication_mode if {
	mode := data.allowed_authentication_modes[_] # regal ignore:unresolved-reference
	authentication_mode == mode
}

authentication_mode := object.get(object.get(object.get(input, "cluster_context", {}), "current", {}), "authentication_mode", "")

title := "EKS cluster should use an approved authentication mode"
description := sprintf("EKS cluster authentication mode should match one of the approved modes: %s", [concat(", ", data.allowed_authentication_modes)]) # regal ignore:unresolved-reference

risk_templates := [{
	"name": "EKS cluster uses a disallowed authentication mode",
	"title": "EKS cluster authentication mode is not in the approved list",
	"statement": "The cluster is using an authentication mode that is not in the organisation's approved list, which may allow legacy ConfigMap-based access that is harder to audit and revoke.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["eks_authentication_mode_not_allowed"],
	"remediation": {
		"title": "Migrate the cluster to an approved authentication mode",
		"description": "EKS authentication mode can be migrated from CONFIG_MAP to API or API_AND_CONFIG_MAP without downtime. Verify all RBAC entries before removing ConfigMap access.",
		"tasks": [
			{"title": "Review existing aws-auth ConfigMap entries"},
			{"title": "Create equivalent EKS access entries via the API"},
			{"title": "Update authentication_mode to API or API_AND_CONFIG_MAP"},
			{"title": "Validate access for all users and service accounts"},
		],
	},
}]
