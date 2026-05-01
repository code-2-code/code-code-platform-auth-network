package oauth

import (
	"encoding/base64"
	"testing"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
	credentialcontract "code-code.internal/platform-contract/credential"
)

func TestResolveOAuthProjectionProjectsArtifactFields(t *testing.T) {
	pkg := &supportv1.CLI{
		CliId: "codex",
		Oauth: &supportv1.OAuthSupport{
			ArtifactProjection: &supportv1.OAuthArtifactProjection{
				FieldMappings: []*supportv1.OAuthArtifactFieldMapping{
					{
						Target:      supportv1.OAuthArtifactTargetField_O_AUTH_ARTIFACT_TARGET_FIELD_ACCOUNT_EMAIL,
						Source:      supportv1.OAuthArtifactSource_O_AUTH_ARTIFACT_SOURCE_ID_TOKEN_CLAIMS,
						JsonPointer: "/email",
					},
					{
						Target:            supportv1.OAuthArtifactTargetField_O_AUTH_ARTIFACT_TARGET_FIELD_ACCOUNT_ID,
						Source:            supportv1.OAuthArtifactSource_O_AUTH_ARTIFACT_SOURCE_ID_TOKEN_CLAIMS,
						JsonPointer:       "/https:~1~1api.openai.com~1auth/chatgpt_account_id",
						FallbackToSubject: true,
					},
				},
			},
		},
	}

	artifact, err := ResolveOAuthProjection(pkg, &credentialcontract.OAuthArtifact{
		AccessToken: "access-token",
		IDToken:     testJWT(`{"sub":"acct-sub","email":"dev@example.com","https://api.openai.com/auth":{"chatgpt_account_id":"acct-1"}}`),
	})
	if err != nil {
		t.Fatalf("ResolveOAuthProjection() error = %v", err)
	}
	if got, want := artifact.AccountEmail, "dev@example.com"; got != want {
		t.Fatalf("account_email = %q, want %q", got, want)
	}
	if got, want := artifact.AccountID, "acct-1"; got != want {
		t.Fatalf("account_id = %q, want %q", got, want)
	}
}

func testJWT(payload string) string {
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
}
