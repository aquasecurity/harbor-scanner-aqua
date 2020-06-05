package harbor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistry_GetBasicCredentials(t *testing.T) {
	testCases := []struct {
		Authorization string

		ExpectedUsername string
		ExpectedPassword string

		ExpectedError string
	}{
		{
			Authorization: "",
			ExpectedError: "parsing authorization: expected <type> <credentials> got []",
		},
		{
			Authorization:    "Basic aGFyYm9yOnMzY3JldA==",
			ExpectedUsername: "harbor",
			ExpectedPassword: "s3cret",
		},
		{
			Authorization: "Basic aGFyYm9yTmFtZQ==",
			ExpectedError: "username and password not split by single colon",
		},
		{
			Authorization: "Basic invalidbase64",
			ExpectedError: "illegal base64 data at input byte 12",
		},
		{
			Authorization: "APIKey 0123456789",
			ExpectedError: "unsupported authorization type: APIKey",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Authorization, func(t *testing.T) {
			username, password, err := Registry{Authorization: tc.Authorization}.GetBasicCredentials()
			switch {
			case tc.ExpectedError != "":
				assert.EqualError(t, err, tc.ExpectedError)
			default:
				require.NoError(t, err)
				assert.Equal(t, tc.ExpectedUsername, username)
				assert.Equal(t, tc.ExpectedPassword, password)
			}

		})
	}
}
