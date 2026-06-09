package compliance_framework.eks_cluster_restrict_public_endpoint_cidrs

violation[{"id": "eks_public_endpoint_not_allowed"}] if {
	public_endpoint_enabled
	not data.allow_public_endpoint
}

violation[{"id": "eks_private_endpoint_required"}] if {
	data.require_private_endpoint_access
	not private_endpoint_enabled
}

violation[{"cidr": cidr, "id": "eks_public_endpoint_broad_cidr"}] if {
	public_endpoint_enabled
	public_access_cidr[cidr]
	broad_public_cidr(cidr)
	not explicitly_allowed_public_cidr(cidr)
}

violation[{"cidr": cidr, "id": "eks_public_endpoint_unapproved_cidr"}] if {
	public_endpoint_enabled
	count(data.allowed_public_endpoint_cidrs) > 0
	public_access_cidr[cidr]
	not explicitly_allowed_public_cidr(cidr)
}

public_endpoint_enabled if {
	object.get(current, "endpoint_public_access", false)
}

private_endpoint_enabled if {
	object.get(current, "endpoint_private_access", false)
}

public_access_cidr[cidr] if {
	cidr := object.get(current, "public_access_cidrs", [])[_]
}

broad_public_cidr(cidr) if {
	cidr == data.broad_public_endpoint_cidrs[_]
}

explicitly_allowed_public_cidr(cidr) if {
	cidr == data.allowed_public_endpoint_cidrs[_]
}

current := object.get(object.get(input, "cluster_context", {}), "current", {})

title := "EKS public endpoint access should be constrained"
description := "EKS cluster public API endpoint access should not use broad CIDRs and should match configured public/private endpoint requirements."
