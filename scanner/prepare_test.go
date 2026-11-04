package scanner

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestPrepareBlob(t *testing.T) {
	plain := []byte("plain text")
	prepared, binaryContent := prepareBlob(plain)
	if binaryContent || string(prepared) != string(plain) {
		t.Fatalf("plain text prepared as %q, binary = %v", prepared, binaryContent)
	}

	content := "token: " + fakeGitHubPAT + "\n"
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		prepared, binaryContent = prepareBlob([]byte(encodedUTF16(content, order)))
		if binaryContent || string(prepared) != content {
			t.Fatalf("UTF-16 prepared as %q, binary = %v", prepared, binaryContent)
		}
	}

	unknown := []byte{0xff, 't', 'e', 'x', 't'}
	prepared, binaryContent = prepareBlob(unknown)
	if binaryContent || string(prepared) != string(unknown) {
		t.Fatalf("unknown encoding prepared as %q, binary = %v", prepared, binaryContent)
	}

	prepared, binaryContent = prepareBlob([]byte("has\x00null"))
	if !binaryContent || prepared != nil {
		t.Fatalf("binary prepared as %q, binary = %v", prepared, binaryContent)
	}
}

func encodedUTF16(content string, order binary.ByteOrder) string {
	units := utf16.Encode([]rune(content))
	data := make([]byte, 2+len(units)*2)
	if order == binary.LittleEndian {
		data[0], data[1] = 0xff, 0xfe
	} else {
		data[0], data[1] = 0xfe, 0xff
	}
	for i, unit := range units {
		order.PutUint16(data[2+i*2:], unit)
	}
	return string(data)
}
