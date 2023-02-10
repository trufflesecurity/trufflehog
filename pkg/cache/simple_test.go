package cache

import "testing"

func TestCache(t *testing.T) {
	tests := []struct {
		name string
		key  string
		val  string
		want string
		ok   bool
	}{
		{"set", "key", "value", "value", true},
		{"get", "key", "", "value", true},
		{"get-not-found", "not-found", "", "", false},
		{"delete", "key", "", "", false},
		{"clear", "key", "", "", false},
	}

	c := Simple()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			switch test.name {
			case "set":
				if err := c.Set(test.key, test.val); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			case "get":
				got, ok := c.Get(test.key)
				if got != test.want || ok != test.ok {
					t.Errorf("got (%q, %t), want (%q, %t)", got, ok, test.want, test.ok)
				}
			case "get-not-found":
				got, ok := c.Get(test.key)
				if got != test.want || ok != test.ok {
					t.Errorf("got (%q, %t), want (%q, %t)", got, ok, test.want, test.ok)
				}
			case "delete":
				if err := c.Delete(test.key); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				got, ok := c.Get(test.key)
				if got != test.want || ok != test.ok {
					t.Errorf("got (%q, %t), want (%q, %t)", got, ok, test.want, test.ok)
				}
			case "clear":
				if err := c.Clear(); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				got, ok := c.Get(test.key)
				if got != test.want || ok != test.ok {
					t.Errorf("got (%q, %t), want (%q, %t)", got, ok, test.want, test.ok)
				}
			}
		})
	}
}
