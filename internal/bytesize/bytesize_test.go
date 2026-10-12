package bytesize

import "testing"

func TestParse(t *testing.T) {
	for in, want := range map[string]int64{
		"0": 0, "1024": 1024, "10GiB": 10 << 30, "10gib": 10 << 30, "1.5MiB": 3 << 19,
		"500MB": 500e6, "2 TB": 2e12, "7b": 7, " 1KiB ": 1024, "1Gi": 1 << 30,
	} {
		got, err := Parse(in)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "GiB", "-1", "10XB", "1.2.3MB", "1e3", "99999999999TiB"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) succeeded", in)
		}
	}
}

func TestFormat(t *testing.T) {
	for n, want := range map[int64]string{
		0: "0B", 300: "300B", 1024: "1KiB", 1536: "1.5KiB", 10 << 30: "10GiB",
		10<<30 + 220<<20: "10.2GiB", 5 << 40: "5TiB", 5 << 50: "5120TiB",
	} {
		if got := Format(n); got != want {
			t.Errorf("Format(%d) = %q, want %q", n, got, want)
		}
	}
}
