package support

import (
	"strings"

	supportv1 "code-code.internal/go-contract/platform/support/v1"
)

func OAuthPolicyID(cli *supportv1.CLI) string {
	if cliID := strings.TrimSpace(cli.GetCliId()); cliID != "" {
		return "cli." + cliID + ".oauth"
	}
	return ""
}
