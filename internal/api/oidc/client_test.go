package oidc

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/query"
)

func roleGrant(projectID string, roles ...string) query.UserGrant {
	return query.UserGrant{
		ProjectID:        projectID,
		Roles:            database.TextArray[string](roles),
		ResourceOwner:    "org1",
		OrgPrimaryDomain: "org1.example.com",
	}
}

func roleKeys(roles projectRoles) []string {
	keys := make([]string, 0, len(roles))
	for key := range roles {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func TestNewProjectRoles(t *testing.T) {
	tests := []struct {
		name string

		projectID      string
		grants         []query.UserGrant
		requestedRoles []string

		wantProjectRoles     map[string][]string
		wantRequestProjectID string
	}{
		{
			// https://github.com/zitadel/zitadel/issues/12673
			// role assertion adds the requesting project's role keys as
			// implicit role scopes; grants of other projects (included
			// through an audience scope) must not be filtered by them.
			name:           "requested roles do not filter other projects",
			projectID:      "a",
			grants:         []query.UserGrant{roleGrant("a", "admin", "user"), roleGrant("b", "admin", "other")},
			requestedRoles: []string{"admin", "user"},

			wantProjectRoles:     map[string][]string{"a": {"admin", "user"}, "b": {"admin", "other"}},
			wantRequestProjectID: "a",
		},
		{
			name:           "requested roles filter the requesting project",
			projectID:      "a",
			grants:         []query.UserGrant{roleGrant("a", "admin", "user")},
			requestedRoles: []string{"admin"},

			wantProjectRoles:     map[string][]string{"a": {"admin"}},
			wantRequestProjectID: "a",
		},
		{
			name:           "no requested roles returns all granted roles",
			projectID:      "a",
			grants:         []query.UserGrant{roleGrant("a", "admin", "user"), roleGrant("b", "admin", "other")},
			requestedRoles: nil,

			wantProjectRoles:     map[string][]string{"a": {"admin", "user"}, "b": {"admin", "other"}},
			wantRequestProjectID: "a",
		},
		{
			name:           "no requesting project keeps filtering all grants",
			projectID:      "",
			grants:         []query.UserGrant{roleGrant("a", "admin", "user"), roleGrant("b", "admin", "other")},
			requestedRoles: []string{"admin"},

			wantProjectRoles:     map[string][]string{"a": {"admin"}, "b": {"admin"}},
			wantRequestProjectID: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newProjectRoles(tt.projectID, tt.grants, tt.requestedRoles)

			gotProjects := make(map[string][]string, len(got.projects))
			for projectID, roles := range got.projects {
				gotProjects[projectID] = roleKeys(roles)
			}
			assert.Equal(t, tt.wantProjectRoles, gotProjects)
			assert.Equal(t, tt.wantRequestProjectID, got.requestProjectID)
		})
	}
}
