package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

type HelperMessage struct {
	Version        int      `json:"schema_version"`
	Nonce          string   `json:"nonce"`
	Sequence       uint64   `json:"sequence"`
	MessageID      string   `json:"message_id,omitempty"`
	HelperInstance string   `json:"helper_instance,omitempty"`
	Kind           string   `json:"kind"`
	Samples        []Sample `json:"samples,omitempty"`
	EnrollmentKey  string   `json:"enrollment_key,omitempty"`
}
type HelperReply struct {
	Version  int     `json:"schema_version"`
	Nonce    string  `json:"nonce"`
	Sequence uint64  `json:"sequence"`
	Policy   *Policy `json:"policy,omitempty"`
	Status   *Status `json:"status,omitempty"`
	State    string  `json:"state"`
	Error    string  `json:"error,omitempty"`
}

const maxFrame = 64 * 1024

func frameDigest(message HelperMessage) (string, error) {
	data, err := json.Marshal(message)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func observationDigest(message HelperMessage) (string, error) {
	message.Nonce = ""
	return frameDigest(message)
}

func validToken(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
func WriteFrame(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxFrame {
		return errors.New("invalid frame size")
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(data)))
	if err = writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, data)
}
func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
func ReadFrame(reader io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.LittleEndian.Uint32(header[:])
	if size == 0 || size > maxFrame {
		return errors.New("invalid frame size")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("invalid frame schema")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("multiple frame values")
	}
	return nil
}
