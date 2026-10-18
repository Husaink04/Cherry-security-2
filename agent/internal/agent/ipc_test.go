package agent

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPipeFrameBoundsAndStrictSchema(t *testing.T) {
	var wire bytes.Buffer
	input := HelperMessage{Version: 1, Nonce: "session", Sequence: 1, Kind: "status"}
	if err := WriteFrame(&wire, input); err != nil {
		t.Fatal(err)
	}
	var output HelperMessage
	if err := ReadFrame(&wire, &output); err != nil || output.Kind != "status" {
		t.Fatalf("frame roundtrip: %v", err)
	}
	for _, payload := range []string{`{"schema_version":1,"unknown":true}`, `{} {}`} {
		wire.Reset()
		binary.Write(&wire, binary.LittleEndian, uint32(len(payload)))
		wire.WriteString(payload)
		if ReadFrame(&wire, &output) == nil {
			t.Fatal("invalid frame accepted")
		}
	}
	wire.Reset()
	binary.Write(&wire, binary.LittleEndian, uint32(65537))
	if ReadFrame(&wire, &output) == nil {
		t.Fatal("oversized frame accepted")
	}
}
