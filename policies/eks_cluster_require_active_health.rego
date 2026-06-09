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

cluster_status := object.get(object.get(input, "cluster_context", {}), "current", {}).status

health_issue_count := object.get(object.get(object.get(input, "cluster_context", {}), "current", {}), "health_issue_count", 0)

title := "EKS cluster should be active and healthy"
description := "EKS cluster status should be ACTIVE and EKS should report no unresolved cluster health issues."
