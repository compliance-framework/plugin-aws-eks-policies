# METADATA
# title: EKS cluster should have required managed add-ons active
# description: Required managed add-ons provide critical cluster networking, DNS, and operational capabilities. Missing or inactive add-ons can disrupt workloads and cluster operations.
# custom:
#   controls:
#     - CC6.7
#     - A1.2
#   schedule: "0 */6 * * *"

package compliance_framework.eks_cluster_require_managed_addons

# data.* keys used here come from policies/data.json, which Regal doesn't read, so their
# references carry a line-scoped Regal ignore for the unresolved-reference rule.

violation[{"addon_name": addon_name, "id": "eks_required_managed_addon_missing"}] if {
	required_addon[addon_name]
	not installed_managed_addon[addon_name]
}

violation[{"addon_name": addon_name, "id": "eks_required_managed_addon_not_active"}] if {
	required_addon[addon_name]
	installed_managed_addon[addon_name]
	not active_managed_addon[addon_name]
}

required_addon[addon_name] if {
	addon_name := data.required_addons[_] # regal ignore:unresolved-reference
}

installed_managed_addon[addon_name] if {
	addon_name := object.get(current, "related_managed_addon_names", [])[_]
}

active_managed_addon[addon_name] if {
	addon_name := object.get(current, "active_related_managed_addon_names", [])[_]
}

skip_reason := "required EKS managed add-ons are not configured" if {
	count(data.required_addons) == 0 # regal ignore:unresolved-reference
}

current := object.get(object.get(input, "cluster_context", {}), "current", {})

title := "EKS cluster should have required managed add-ons active"
description := sprintf("EKS cluster should have required managed add-ons installed and active: %s", [concat(", ", data.required_addons)]) # regal ignore:unresolved-reference

risk_templates := [
	{
		"name": "Required EKS managed add-on not installed",
		"title": "Required EKS managed add-on is missing from the cluster",
		"statement": "A required EKS managed add-on is not installed on the cluster. Missing add-ons may cause networking, DNS, or operational disruptions.",
		"likelihood_hint": "low",
		"impact_hint": "high",
		"violation_ids": ["eks_required_managed_addon_missing"],
		"remediation": {
			"title": "Install the missing required managed add-on",
			"description": "Install the missing add-on via the EKS console or AWS CLI. Verify that an appropriate IAM role is associated if the add-on requires service account access.",
			"tasks": [
				{"title": "Identify the missing add-on name from the violation details"},
				{"title": "Install the add-on via the EKS console or AWS CLI"},
				{"title": "Verify the add-on reaches ACTIVE status"},
			],
		},
	},
	{
		"name": "Required EKS managed add-on not active",
		"title": "Required EKS managed add-on is installed but not active",
		"statement": "A required EKS managed add-on is installed but not in an ACTIVE state, which may indicate a configuration or version compatibility issue.",
		"likelihood_hint": "medium",
		"impact_hint": "high",
		"violation_ids": ["eks_required_managed_addon_not_active"],
		"remediation": {
			"title": "Investigate and restore the add-on to ACTIVE state",
			"description": "Review the add-on health status and events to identify the cause of the degraded state.",
			"tasks": [
				{"title": "Check add-on status and health events in the EKS console"},
				{"title": "Update the add-on to a compatible version if applicable"},
				{"title": "Verify the add-on reaches ACTIVE status after remediation"},
			],
		},
	},
]
