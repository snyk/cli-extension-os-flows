//nolint:revive // var-naming and exported rules
package testapiinline

import (
	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

type FindingRelationship = struct {
	Asset *struct {
		Data *struct {
			Id   uuid.UUID "json:\"id\""
			Type string    "json:\"type\""
		} "json:\"data,omitempty\""
		Links testapi.IoSnykApiCommonRelatedLink "json:\"links\""
		Meta  *testapi.IoSnykApiCommonMeta       "json:\"meta,omitempty\""
	} "json:\"asset,omitempty\""
	Fix *RelationshipFix "json:\"fix,omitempty\""
	Org *struct {
		Data *struct {
			Id   uuid.UUID "json:\"id\""
			Type string    "json:\"type\""
		} "json:\"data,omitempty\""
	} "json:\"org,omitempty\""
	Policy *PolicyRelationship `json:"policy,omitempty"`
	Test   *struct {
		Data *struct {
			Id   uuid.UUID "json:\"id\""
			Type string    "json:\"type\""
		} "json:\"data,omitempty\""
		Links testapi.IoSnykApiCommonRelatedLink "json:\"links\""
		Meta  *testapi.IoSnykApiCommonMeta       "json:\"meta,omitempty\""
	} "json:\"test,omitempty\""
}

type PolicyRelationship = struct {
	Data  *PolicyRelationshipData            `json:"data,omitempty"`
	Links testapi.IoSnykApiCommonRelatedLink `json:"links"`

	// Meta Free-form object that may contain non-standard information.
	Meta *testapi.IoSnykApiCommonMeta `json:"meta,omitempty"`
}

type PolicyRelationshipData = struct {
	// Attributes Inlined attributes included in the relationship, if it is expanded.
	//
	// Expansion is a Snyk variation on JSON API. See
	// https://snyk.roadie.so/docs/default/component/sweater-comb/standards/rest/#expansion
	Attributes *testapi.PolicyAttributes `json:"attributes,omitempty"`
	Id         uuid.UUID                 `json:"id"`
	Type       string                    `json:"type"`
}

type FixData = struct {
	Attributes *testapi.FixAttributes "json:\"attributes,omitempty\""
	Id         uuid.UUID              "json:\"id\""
	Type       string                 "json:\"type\""
}

type RelationshipFix = struct {
	Data *FixData "json:\"data,omitempty\""
}
