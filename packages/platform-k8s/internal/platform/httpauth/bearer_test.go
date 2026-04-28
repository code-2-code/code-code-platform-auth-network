package httpauth

import (
	"net/http"
	"testing"
)

func TestHasBearerAuthorization(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		header string
		token  string
		want   bool
	}{
		{name: "empty header", header: "", token: "secret", want: false},
		{name: "empty token", header: "Bearer secret", token: "", want: false},
		{name: "non bearer header", header: "Basic xyz", token: "secret", want: false},
		{name: "wrong token", header: "Bearer other", token: "secret", want: false},
		{name: "valid token", header: "Bearer secret", token: "secret", want: true},
		{name: "case insensitive prefix", header: "bEaReR secret", token: "secret", want: true},
	}
	for _, item := range cases {
		item := item
		t.Run(item.name, func(t *testing.T) {
			t.Parallel()
			if got := HasBearerAuthorization(item.header, item.token); got != item.want {
				t.Fatalf("HasBearerAuthorization(%q, %q) = %v, want %v", item.header, item.token, got, item.want)
			}
		})
	}
}

func TestSetBearerAuthorization(t *testing.T) {
	t.Parallel()

	request, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	SetBearerAuthorization(request, "secret")
	if got, want := request.Header.Get("Authorization"), "Bearer secret"; got != want {
		t.Fatalf("authorization = %q, want %q", got, want)
	}
	SetBearerAuthorization(request, "")
	if got, want := request.Header.Get("Authorization"), "Bearer secret"; got != want {
		t.Fatalf("authorization after empty token = %q, want %q", got, want)
	}
}
