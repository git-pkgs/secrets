package scanner

import (
	"encoding/binary"
	"github.com/git-pkgs/magic"
	"unicode/utf16"
)

func prepareBlob(data []byte) ([]byte, bool) {
	result := magic.Detect(data)
	if result.Kind == magic.KindBinary {
		return nil, true
	}
	switch result.Encoding {
	case magic.EncodingUTF16LE:
		return decodeUTF16(data[2:], binary.LittleEndian), false
	case magic.EncodingUTF16BE:
		return decodeUTF16(data[2:], binary.BigEndian), false
	default:
		return data, false
	}
}

func decodeUTF16(data []byte, order binary.ByteOrder) []byte {
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = order.Uint16(data[i*2:])
	}
	return []byte(string(utf16.Decode(units)))
}
