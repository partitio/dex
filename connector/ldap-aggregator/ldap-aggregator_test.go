package ldapaggregator

import "testing"

func TestUsernamePrompt(t *testing.T) {
	tests := map[string]struct {
		config   Config
		expected string
	}{
		"with usernamePrompt unset it returns \"\"": {
			config:   Config{},
			expected: "",
		},
		"with usernamePrompt set it returns that": {
			config:   Config{UsernamePrompt: "Email address"},
			expected: "Email address",
		},
	}

	for n, d := range tests {
		t.Run(n, func(t *testing.T) {
			conn := &ldapConnector{Config: d.config}
			if actual := conn.Prompt(); actual != d.expected {
				t.Errorf("expected %v, got %v", d.expected, actual)
			}
		})
	}
}
