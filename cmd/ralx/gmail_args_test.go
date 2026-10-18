package main

import (
	"reflect"
	"testing"
)

// A flag with no value must be a usage error, not part of the query or a
// silent fallback to the default account.
func TestGmailSearchArgs(t *testing.T) {
	ok := []struct {
		in   []string
		want map[string]any
	}{
		{[]string{"invoice", "-label:spam"}, map[string]any{"q": "invoice -label:spam"}},
		{[]string{"invoice", "--account", "a@b.com", "--max", "5"}, map[string]any{"q": "invoice", "account": "a@b.com", "max": 5}},
		{[]string{"--account=a@b.com", "from:x", "--max=3"}, map[string]any{"q": "from:x", "account": "a@b.com", "max": 3}},
	}
	for _, c := range ok {
		got, err := gmailSearchArgs(c.in)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: got %v, %v; want %v", c.in, got, err, c.want)
		}
	}
	for _, in := range [][]string{
		{"invoice", "--account"},
		{"invoice", "--account="},
		{"invoice", "--max"},
		{"invoice", "--max="},
		{"invoice", "--max", "lots"},
	} {
		if got, err := gmailSearchArgs(in); err == nil {
			t.Errorf("%q: want a usage error, got %v", in, got)
		}
	}
}
