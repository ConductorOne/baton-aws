package connector

import (
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

func paginate[RV any](rv RV, bag *pagination.Bag, pageToken *string) (RV, string, annotations.Annotations, error) {
	if pageToken == nil || *pageToken == "" {
		return rv, "", nil, nil
	}

	token, err := bag.NextToken(*pageToken)
	if err != nil {
		return rv, "", nil, err
	}

	return rv, token, nil, nil
}

func paginateTruncation[RV any](rv RV, bag *pagination.Bag, pageToken *string, isTruncated bool) (RV, string, annotations.Annotations, error) {
	if !isTruncated {
		return rv, "", nil, nil
	}

	return paginate(rv, bag, pageToken)
}
