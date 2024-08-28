package connector

import v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"

var (
	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "IAM Role",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
		Annotations: v1AnnotationsForResourceType("role"),
	}
	resourceTypeIAMGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
		Annotations: v1AnnotationsForResourceType("group"),
	}
	resourceTypeSSOGroup = &v2.ResourceType{
		Id:          "sso_group",
		DisplayName: "SSO Group",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_GROUP,
		},
		Annotations: v1AnnotationsForResourceType("sso_group"),
	}
	resourceTypeAccount = &v2.ResourceType{
		Id:          "account", // this is "application" in c1
		DisplayName: "Account",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_APP},
		Annotations: v1AnnotationsForResourceType("account"),
	}
	resourceTypeSSOUser = &v2.ResourceType{
		Id:          "sso_user",
		DisplayName: "SSO User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: v1AnnotationsForResourceType("sso_user"),
	}
	resourceTypeIAMUser = &v2.ResourceType{
		Id:          "iam_user",
		DisplayName: "IAM User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: v1AnnotationsForResourceType("iam_user"),
	}
)
