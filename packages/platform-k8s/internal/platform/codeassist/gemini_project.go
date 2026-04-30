package codeassist

import "strings"

func geminiProjectIDFromProjectValue(raw any) string {
	switch value := raw.(type) {
	case string:
		return geminiNormalizeProjectID(value)
	case map[string]any:
		for _, key := range []string{"id", "projectId", "name"} {
			if id, ok := value[key].(string); ok {
				if projectID := geminiNormalizeProjectID(id); projectID != "" {
					return projectID
				}
			}
		}
	}
	return ""
}

func geminiNormalizeProjectID(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "projects/") {
		return strings.TrimSpace(strings.TrimPrefix(trimmed, "projects/"))
	}
	const projectSegment = "/projects/"
	if index := strings.LastIndex(trimmed, projectSegment); index >= 0 {
		return strings.TrimSpace(trimmed[index+len(projectSegment):])
	}
	return trimmed
}
