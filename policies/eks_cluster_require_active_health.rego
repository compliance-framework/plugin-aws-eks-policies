# METADATA
# title: EKS cluster should be active and healthy
# description: An EKS cluster that is not ACTIVE or has unresolved health issues may be degraded or unavailable, affecting workloads and control plane operations.
# custom:
#   controls:
#     - A1.2
#     - CC7.2
#   schedule: "0 */6 * * *"

package compliance_framework.eks_cluster_require_active_health

violation[{"id": "eks_cluster_not_active"}] if {
	not approved_cluster_status
}

violation[{"id": "eks_cluster_health_issues_present"}] if {
	health_issue_count > 0
}

approved_cluster_status if {
	status := data.approved_cluster_statuses[_]
	cluster_status == status
}

cluster_status := object.get(object.get(object.get(input, "cluster_context", {}), "current", {}), "status", "")

health_issue_count := object.get(object.get(object.get(input, "cluster_context", {}), "current", {}), "health_issue_count", 0)

title := "EKS cluster should be active and healthy"
description := "EKS cluster status should be ACTIVE and EKS should report no unresolved cluster health issues."

risk_templates := [
	{
		"name":            "EKS cluster is not active",
		"title":           "EKS cluster is not in ACTIVE state",
		"statement":       "The cluster is not reporting an ACTIVE status, which may indicate an ongoing control plane operation, provisioning failure, or degraded state affecting workload availability.",
		"likelihood_hint": "low",
		"impact_hint":     "high",
		"violation_ids":   ["eks_cluster_not_active"],
		"remediation": {
			"title":       "Investigate and restore cluster to ACTIVE state",
			"description": "Review EKS cluster events and the AWS health dashboard to identify the cause of the non-ACTIVE state.",
			"tasks": [
				{"title": "Check EKS cluster status and events in the AWS console"},
				{"title": "Review CloudTrail for recent API calls that may have changed cluster state"},
				{"title": "Contact AWS support if the cluster is stuck in a transitional state"}
			]
		}
	},
	{
		"name":            "EKS cluster has unresolved health issues",
		"title":           "EKS cluster has unresolved health issues reported by AWS",
		"statement":       "AWS has reported one or more unresolved health issues for this cluster that may affect control plane operations or workload scheduling.",
		"likelihood_hint": "medium",
		"impact_hint":     "high",
		"violation_ids":   ["eks_cluster_health_issues_present"],
		"remediation": {
			"title":       "Resolve EKS cluster health issues",
			"description": "Review the EKS cluster health dashboard for specific issue codes and follow AWS remediation guidance for each issue type.",
			"tasks": [
				{"title": "Review cluster health issues via the EKS console or AWS CLI"},
				{"title": "Address the root cause of each reported health issue"},
				{"title": "Verify health issue count returns to zero after remediation"}
			]
		}
	},
]
