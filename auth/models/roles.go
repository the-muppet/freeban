package models

import "encoding/json"

type UserRole string

const (
	RoleApi UserRole = "api"

	RoleTest    UserRole = "test"
	RoleFree    UserRole = "free"
	RolePioneer UserRole = "pioneer"
	RoleModern  UserRole = "modern"
	RoleLegacy  UserRole = "legacy"
	RoleVintage UserRole = "vintage"
	RoleAdmin   UserRole = "admin"
)

var RoleHierarchy = map[UserRole][]UserRole{
	RoleFree:    {},
	RolePioneer: {RoleFree},

	RoleModern:  {RoleFree, RolePioneer},
	RoleLegacy:  {RoleFree, RolePioneer, RoleModern},
	RoleVintage: {RoleFree, RolePioneer, RoleModern, RoleLegacy},
	RoleAdmin:   {RoleFree, RolePioneer, RoleModern, RoleLegacy, RoleVintage},
}

func (r UserRole) String() string {
	return string(r)
}

func (r UserRole) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r *UserRole) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*r = UserRole(s)
	return nil

}

func (r UserRole) IsValid() bool {
	switch r {
	case RoleApi, RoleTest, RoleFree, RolePioneer, RoleModern, RoleLegacy, RoleVintage, RoleAdmin:
		return true
	}
	return false

}
