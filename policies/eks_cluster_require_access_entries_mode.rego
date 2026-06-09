package compliance_framework.eks_cluster_require_access_entries_mode

violation[{"authentication_mode": authentication_mode, "id": "eks_authentication_mode_not_allowed"}] if {
	not allowed_authentication_mode
}

allowed_authentication_mode if {
	mode := data.allowed_authentication_modes[_]
	authentication_mode == mode
}

authentication_mode := object.get(object.get(object.get(input, "cluster_context", {}), "current", {}), "authentication_mode", "")

title := "EKS cluster should use an approved authentication mode"
description := sprintf("EKS cluster authentication mode should match one of the approved modes: %s", [concat(", ", data.allowed_authentication_modes)])
