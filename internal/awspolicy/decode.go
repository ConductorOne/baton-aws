// Package awspolicy decodes IAM policy documents as returned by the AWS APIs.
package awspolicy

import (
	"encoding/json"
	"net/url"
)

// DecodePolicyDocument returns an IAM policy document in JSON form.
func DecodePolicyDocument(document string) (string, error) {
	if json.Valid([]byte(document)) {
		return document, nil
	}
	// IAM APIs return policy documents URL-encoded per RFC 3986, so '+' is a
	// literal plus, not a space. PathUnescape is used instead of QueryUnescape.
	decoded, err := url.PathUnescape(document)
	if err != nil {
		return "", err
	}
	return decoded, nil
}
