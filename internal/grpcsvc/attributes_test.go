// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import "testing"

// A record with no attributes is stored as an object, never JSON null: readers
// of the column (the appliance's data-move chain check) take it as an object.
func TestAttributesAreStoredAsAnObject(t *testing.T) {
	for name, tc := range map[string]struct {
		in   map[string]string
		want string
	}{
		"nil map":   {nil, `{}`},
		"empty map": {map[string]string{}, `{}`},
		"keys":      {map[string]string{"b": "2", "a": "1"}, `{"a":"1","b":"2"}`},
	} {
		if got := string(attributesJSON(tc.in)); got != tc.want {
			t.Errorf("%s: stored %s, want %s", name, got, tc.want)
		}
	}
}
