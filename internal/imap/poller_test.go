package imap

import (
	"os"
	"path/filepath"
	"testing"
)

// ── safeFilename ──────────────────────────────────────────────────────────

func TestSafeFilename_Normal(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "1"), 0750)

	dest, err := safeFilename(dir, 1, "document.pdf")
	if err != nil {
		t.Fatalf("safeFilename normal: %v", err)
	}
	if filepath.Dir(dest) != filepath.Join(dir, "1") {
		t.Errorf("dest not in expected dir: %s", dest)
	}
	if filepath.Base(dest) != "document.pdf" {
		t.Errorf("unexpected base name: %s", filepath.Base(dest))
	}
}

func TestSafeFilename_StripDirectoryComponents(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "1"), 0750)

	// Attempt path traversal via directory separators
	dest, err := safeFilename(dir, 1, "../../etc/passwd")
	if err != nil {
		t.Fatalf("expected safeFilename to strip path, got error: %v", err)
	}
	// Should have stripped to just "passwd"
	if filepath.Base(dest) != "passwd" {
		t.Errorf("expected base=passwd, got %s", filepath.Base(dest))
	}
	// Must still be inside the attach dir
	if !isInsideDir(dest, dir) {
		t.Errorf("dest %q escapes attachDir %q", dest, dir)
	}
}

func TestSafeFilename_AbsolutePath(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "1"), 0750)

	// Absolute path in filename — should be stripped to base name
	dest, err := safeFilename(dir, 1, "/etc/passwd")
	if err != nil {
		t.Fatalf("absolute path: %v", err)
	}
	if !isInsideDir(dest, dir) {
		t.Errorf("dest %q escapes attachDir %q", dest, dir)
	}
}

func TestSafeFilename_EmptyName(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "1"), 0750)

	dest, err := safeFilename(dir, 1, "")
	if err != nil {
		t.Fatalf("empty name: %v", err)
	}
	if filepath.Base(dest) != "attachment" {
		t.Errorf("empty name should fall back to 'attachment', got %s", filepath.Base(dest))
	}
}

func TestSafeFilename_DotDotName(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "1"), 0750)

	// Pure ".." as filename
	dest, err := safeFilename(dir, 1, "..")
	// Either it returns an error OR the result is inside the dir
	if err == nil && !isInsideDir(dest, dir) {
		t.Errorf(".. filename escaped attachDir: %s", dest)
	}
}

func TestSafeFilename_PreservesExtension(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "5"), 0750)

	dest, err := safeFilename(dir, 5, "report.xlsx")
	if err != nil {
		t.Fatalf("safeFilename: %v", err)
	}
	if filepath.Ext(dest) != ".xlsx" {
		t.Errorf("extension not preserved: got %s", filepath.Ext(dest))
	}
}

// ── normalisedAddr ────────────────────────────────────────────────────────

func TestNormalisedAddr(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"alice@example.com", "alice@example.com"},
		{"ALICE@EXAMPLE.COM", "alice@example.com"},
		{"Alice <Alice@Example.COM>", "alice@example.com"},
		{"  bob@example.com  ", "bob@example.com"},
		{"Name <Name@Domain.ORG>", "name@domain.org"},
		// Malformed — falls back to lowercased raw
		{"notanemail", "notanemail"},
		{"", ""},
	}
	for _, tt := range tests {
		got := normalisedAddr(tt.input)
		if got != tt.want {
			t.Errorf("normalisedAddr(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

func isInsideDir(path, dir string) bool {
	clean := filepath.Clean(dir) + string(filepath.Separator)
	return len(path) > len(clean) && path[:len(clean)] == clean
}
