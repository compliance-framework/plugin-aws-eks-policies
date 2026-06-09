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
