package gocircuitexternal

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"time"
)

type qrParser struct {
	uncompressedData []byte
}

func newQRParser(data *big.Int) (*qrParser, error) {
	r, err := zlib.NewReader(bytes.NewReader(data.Bytes()))
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %w", err)
	}
	uncompressedData, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read compressed, data: %w", err)
	}
	if err = r.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zlib reader: %w", err)
	}

	return &qrParser{uncompressedData}, nil
}

func (q *qrParser) payload() (
	dataPadded []byte,
	dataPaddedLen int,
	delimiterIndices []int,
	signature *big.Int,
	err error,
) {
	signature = big.NewInt(0).SetBytes(q.uncompressedData[len(q.uncompressedData)-256:])
	signetData := q.uncompressedData[:len(q.uncompressedData)-256]
	dataPadded, dataPaddedLen, err = sha256Pad(signetData, 512*3)
	if err != nil {
		return
	}

	for i, b := range signetData {
		if b == 255 {
			delimiterIndices = append(delimiterIndices, i)
		}
		if len(delimiterIndices) == 18 {
			break
		}
	}
	return dataPadded, dataPaddedLen, delimiterIndices, signature, nil
}

func (q *qrParser) fields() (*QrCodeFields, error) {
	data, _, _, _, err := q.payload()
	if err != nil {
		return nil, fmt.Errorf("failed to extract payload: %w", err)
	}
	f := &QrCodeFields{}
	if err = f.Parse(data); err != nil {
		return nil, fmt.Errorf("failed to parse fields: %w", err)
	}
	return f, nil
}

type QrCodeFields struct {
	Birthday *big.Int
	Gender   *big.Int
	Pincode  *big.Int
	State    *big.Int
}

func (q *QrCodeFields) Parse(payload []byte) error {
	var err error
	q.Birthday, err = birthday(payload)
	if err != nil {
		return fmt.Errorf("failed to parse birthday: %w", err)
	}
	q.Pincode, err = pincode(payload)
	if err != nil {
		return fmt.Errorf("failed to parse pincode: %w", err)
	}
	q.Gender = gender(payload)
	q.State = state(payload)
	return nil
}

func birthday(d []byte) (*big.Int, error) {
	rawTime := string(d[39:49])
	t, err := time.Parse("01-02-2006", rawTime)
	if err != nil {
		return nil, fmt.Errorf("failed to parse time '%s': %w", rawTime, err)
	}
	return big.NewInt(
		int64(t.Year()*10000 + int(t.Month())*100 + t.Day()),
	), nil
}

func gender(d []byte) *big.Int {
	return big.NewInt(int64(d[50]))
}

func pincode(d []byte) (*big.Int, error) {
	rawPincode := string(d[98:104])
	i, err := strconv.Atoi(rawPincode)
	if err != nil {
		return nil, fmt.Errorf("failed to parse int '%s': %w", rawPincode, err)
	}
	return big.NewInt(int64(i)), nil
}

func state(d []byte) *big.Int {
	return big.NewInt(0).SetBytes(reverseBytes(d[119:124]))
}

// golang implementation of sha256Pad from zk-email helpers
// https://github.com/zkemail/zk-email-verify/blob/e1084969fbee16317290e4380b3837af74fea616/packages/helpers/src/sha-utils.ts#L88
func sha256Pad(m []byte, maxShaBytes int) (paddedMessage []byte, messageLen int, err error) {
	// do not modify the original message
	message := make([]byte, len(m))
	copy(message, m)

	msgLen := len(message) * 8
	msgLenBytes := int64ToBytes(int64(msgLen))

	paddedMessage = append(message, 0x80)
	for ((len(paddedMessage)*8 + len(msgLenBytes)*8) % 512) != 0 {
		paddedMessage = append(paddedMessage, 0x00)
	}

	paddedMessage = append(paddedMessage, msgLenBytes...)
	if len(paddedMessage)*8%512 != 0 {
		return nil, 0, errors.New("padding did not complete properly")
	}

	messageLen = len(paddedMessage)
	for len(paddedMessage) < maxShaBytes {
		paddedMessage = append(paddedMessage, int64ToBytes(0)...)
	}
	if len(paddedMessage) != maxShaBytes {
		return nil, 0, fmt.Errorf("padding to max length did not complete properly: got %d, expected %d", len(paddedMessage), maxShaBytes)
	}

	return paddedMessage, messageLen, nil
}
