package api

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMimeType_String(t *testing.T) {
	testCases := []struct {
		mimeType       MimeType
		expectedString string
	}{
		{
			mimeType:       MimeType{Type: "application", Subtype: "vnd.scanner.adapter.scan.request+json"},
			expectedString: "application/vnd.scanner.adapter.scan.request+json",
		},
		{
			mimeType:       MimeType{Type: "application", Subtype: "vnd.scanner.adapter.scan.request+json", Params: MimeTypeParams{"version": "1.0"}},
			expectedString: "application/vnd.scanner.adapter.scan.request+json; version=1.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.expectedString, func(t *testing.T) {
			assert.Equal(t, tc.expectedString, tc.mimeType.String())
		})
	}
}

func TestBaseHandler_WriteJSONError(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler := &BaseHandler{}

	handler.WriteJSONError(recorder, harbor.Error{
		HTTPCode: http.StatusBadRequest,
		Message:  "Invalid request",
	})

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.JSONEq(t, `{"error":{"message":"Invalid request"}}`, recorder.Body.String())
}

func TestBaseHandler_SendInternalServerError(t *testing.T) {
	recorder := httptest.NewRecorder()
	handler := &BaseHandler{}

	handler.SendInternalServerError(recorder)

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Equal(t, "Internal Server Error\n", recorder.Body.String())
}
