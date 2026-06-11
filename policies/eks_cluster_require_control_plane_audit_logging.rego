# METADATA
# title: EKS cluster should enable required control plane logs
# description: EKS control plane logs provide visibility into API server activity, authentication events, and scheduler decisions. Missing log types reduce forensic and monitoring capability.
# custom:
#   controls:
#     - CC7.2
#     - CC7.3
#   schedule: "0 */6 * * *"

package compliance_framework.eks_cluster_require_control_plane_audit_logging

violation[{"id": "eks_control_plane_log_type_missing", "log_type": log_type}] if {
	required_log_type[log_type]
	not enabled_log_type[log_type]
}

required_log_type[log_type] if {
	log_type := data.required_control_plane_log_types[_]
}

enabled_log_type[log_type] if {
	log_type := object.get(object.get(object.get(input, "cluster_context", {}), "current", {}), "enabled_control_plane_log_types", [])[_]
}

skip_reason := "required EKS control plane log types are not configured" if {
	count(data.required_control_plane_log_types) == 0
}

title := "EKS cluster should enable required control plane logs"
description := sprintf("EKS control plane logging should include required log types: %s", [concat(", ", data.required_control_plane_log_types)])

risk_templates := [{
	"name":            "EKS control plane log type is disabled",
	"title":           "Required EKS control plane log type is not enabled",
	"statement":       "One or more required EKS control plane log types are not enabled, reducing visibility into API server events, authentication activity, and cluster operations.",
	"likelihood_hint": "medium",
	"impact_hint":     "high",
	"violation_ids":   ["eks_control_plane_log_type_missing"],
	"remediation": {
		"title":       "Enable all required control plane log types",
		"description": "Enable the missing log types in the EKS cluster logging configuration. Logs are streamed to CloudWatch Logs at no EKS charge (CloudWatch ingestion costs apply).",
		"tasks": [
			{"title": "Identify missing log types from the violation details"},
			{"title": "Enable the missing log types via the EKS console or AWS CLI"},
			{"title": "Verify logs are appearing in the associated CloudWatch log group"}
		]
	}
}]
