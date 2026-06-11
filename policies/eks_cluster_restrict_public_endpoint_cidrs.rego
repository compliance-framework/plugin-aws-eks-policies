# METADATA
# title: EKS public endpoint access should be constrained
# description: Broadly accessible EKS API server endpoints increase the attack surface. Restricting public access to approved CIDRs or disabling the public endpoint reduces exposure to unauthorised access.
# custom:
#   controls:
#     - CC6.6
#     - CC6.7
#   schedule: "0 */6 * * *"

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

risk_templates := [
	{
		"name":            "EKS public endpoint not permitted",
		"title":           "EKS cluster has a public API endpoint but public access is not permitted by policy",
		"statement":       "The EKS API server has a public endpoint enabled, but organisational policy does not permit public endpoint access for this cluster.",
		"likelihood_hint": "medium",
		"impact_hint":     "high",
		"violation_ids":   ["eks_public_endpoint_not_allowed"],
		"remediation": {
			"title":       "Disable the EKS cluster public endpoint",
			"description": "Enable private endpoint access before disabling the public endpoint to avoid losing API server connectivity.",
			"tasks": [
				{"title": "Enable private endpoint access in the cluster networking configuration"},
				{"title": "Disable public endpoint access"},
				{"title": "Verify cluster operations continue via the private endpoint"}
			]
		}
	},
	{
		"name":            "EKS private endpoint not enabled",
		"title":           "EKS cluster does not have private endpoint access enabled",
		"statement":       "Policy requires private endpoint access to be enabled so that in-cluster workloads can reach the Kubernetes API server without traversing the public internet.",
		"likelihood_hint": "low",
		"impact_hint":     "high",
		"violation_ids":   ["eks_private_endpoint_required"],
		"remediation": {
			"title":       "Enable EKS cluster private endpoint access",
			"description": "Enable private endpoint access in the cluster networking configuration.",
			"tasks": [
				{"title": "Enable private endpoint access in the EKS cluster networking settings"},
				{"title": "Verify node-to-API-server connectivity via the private endpoint"}
			]
		}
	},
	{
		"name":            "EKS public endpoint uses broad CIDR",
		"title":           "EKS cluster public endpoint is accessible from a broad CIDR range",
		"statement":       "The EKS API server public endpoint allows access from a broad CIDR (e.g. 0.0.0.0/0), exposing it to the entire internet and increasing the risk of credential-based attacks against the Kubernetes API.",
		"likelihood_hint": "high",
		"impact_hint":     "high",
		"violation_ids":   ["eks_public_endpoint_broad_cidr"],
		"threat_refs": [
			{
				"system":      "https://cwe.mitre.org",
				"external_id": "CWE-284",
				"title":       "Improper Access Control",
				"url":         "https://cwe.mitre.org/data/definitions/284.html"
			}
		],
		"remediation": {
			"title":       "Restrict EKS public endpoint CIDRs to known ranges",
			"description": "Replace broad CIDRs with specific IP ranges covering only authorised operators and CI/CD infrastructure.",
			"tasks": [
				{"title": "Identify all IP ranges that legitimately need API server access"},
				{"title": "Update allowed_public_endpoint_cidrs to the identified ranges"},
				{"title": "Remove broad CIDRs (0.0.0.0/0, ::/0) from the public access CIDR list"}
			]
		}
	},
	{
		"name":            "EKS public endpoint CIDR not in approved list",
		"title":           "EKS cluster public endpoint allows access from an unapproved CIDR",
		"statement":       "The EKS API server public endpoint allows access from a CIDR that is not in the organisation's approved list, potentially exposing it to unauthorised networks.",
		"likelihood_hint": "medium",
		"impact_hint":     "high",
		"violation_ids":   ["eks_public_endpoint_unapproved_cidr"],
		"remediation": {
			"title":       "Remove unapproved CIDRs from the EKS public endpoint allowlist",
			"description": "Update the cluster endpoint access configuration to remove CIDRs not in the allowed_public_endpoint_cidrs policy list.",
			"tasks": [
				{"title": "Review the current public endpoint CIDR list"},
				{"title": "Remove any CIDRs not present in the allowed_public_endpoint_cidrs policy"},
				{"title": "Verify all required operators and CI/CD systems can still reach the API server"}
			]
		}
	},
]
