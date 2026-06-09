package compliance_framework.eks_cluster_require_managed_addons

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
	addon_name := data.required_addons[_]
}

installed_managed_addon[addon_name] if {
	addon_name := object.get(current, "related_managed_addon_names", [])[_]
}

active_managed_addon[addon_name] if {
	addon_name := object.get(current, "active_related_managed_addon_names", [])[_]
}

skip_reason := "required EKS managed add-ons are not configured" if {
	count(data.required_addons) == 0
}

current := object.get(object.get(input, "cluster_context", {}), "current", {})

title := "EKS cluster should have required managed add-ons active"
description := sprintf("EKS cluster should have required managed add-ons installed and active: %s", [concat(", ", data.required_addons)])
