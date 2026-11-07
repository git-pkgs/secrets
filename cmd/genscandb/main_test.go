package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCompressedDatabase(t *testing.T) {
	output := filepath.Join(t.TempDir(), "scan.db.gz")
	want := bytes.Repeat([]byte("compiled scanner database\n"), 100)
	size, err := writeCompressedDatabase(output, want)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if size != len(compressed) {
		t.Fatalf("reported compressed size is %d, file size is %d", size, len(compressed))
	}
	if len(compressed) >= len(want) {
		t.Fatalf("compressed database is %d bytes, uncompressed database is %d", len(compressed), len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatal("decompressed database differs from input")
	}
}
