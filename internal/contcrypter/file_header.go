package contcrypter

// Per-file header
//
// Format: [ "Version" uint16 big endian ] [ "Id" 16 random bytes ]

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"log"
	"syscall"

	"github.com/Declan94/cfcryptfs/corecrypter"
	"github.com/Declan94/cfcryptfs/internal/tlog"
)

const (
	// CurrentVersion is the current On-Disk-Format version
	CurrentVersion = 0

	headerVersionLen    = 2  // uint16
	headerIDLen         = 16 // 128 bit random file id
	headerPropertiesLen = 16 // 4 bytes mode, 12 bytes reserved
	headerSignLen       = md5.Size
	// HeaderLen is the total header length
	HeaderLen = headerVersionLen + headerIDLen + headerPropertiesLen + headerSignLen
)

// FileHeader represents the header stored on each non-empty file.
type FileHeader struct {
	Version uint16
	FileID  []byte
	Mode    uint32
	sign    []byte
}

// NewFileHeader - create new fileHeader object with random Id
func NewFileHeader(mode uint32) *FileHeader {
	var h FileHeader
	h.Version = CurrentVersion
	h.FileID = corecrypter.RandBytes(headerIDLen)
	h.Mode = mode
	h.sign = make([]byte, headerSignLen)
	return &h
}

// Pack - sign and serialize fileHeader object
func (h *FileHeader) Pack() []byte {
	if len(h.FileID) != headerIDLen || h.Version != CurrentVersion {
		log.Panic("FileHeader object not properly initialized")
	}
	buf := make([]byte, HeaderLen)
	p := 0
	binary.BigEndian.PutUint16(buf[p:], h.Version)
	p += headerVersionLen
	copy(buf[p:], h.FileID)
	p += headerIDLen
	binary.BigEndian.PutUint32(buf[p:], h.Mode)
	p += headerPropertiesLen
	mac := hmac.New(md5.New, h.FileID)
	mac.Write(buf[:p])
	sign := mac.Sum(nil)
	copy(buf[p:], sign)
	return buf
}

// ParseHeader - parse "buf" into fileHeader object
func ParseHeader(buf []byte) (*FileHeader, error) {
	if len(buf) != HeaderLen {
		tlog.Warn.Printf("ParseHeader: invalid length: want %d bytes, got %d. Returning EINVAL.", HeaderLen, len(buf))
		return nil, syscall.EINVAL
	}
	var h FileHeader
	p := 0
	h.Version = binary.BigEndian.Uint16(buf[p : p+headerVersionLen])
	p += headerVersionLen
	h.FileID = buf[p : p+headerIDLen]
	p += headerIDLen
	h.Mode = binary.BigEndian.Uint32(buf[p : p+4])
	p += headerPropertiesLen
	h.sign = buf[p:]
	mac := hmac.New(md5.New, h.FileID)
	mac.Write(buf[:p])
	expectedSign := mac.Sum(nil)
	if !hmac.Equal(expectedSign, h.sign) {
		tlog.Warn.Printf("ParseHeader: invalid header signature, has file been manually modified?. Returning EINVAL.")
		return nil, syscall.EINVAL
	}
	if h.Version != CurrentVersion {
		tlog.Warn.Printf("ParseHeader: invalid version: want %d, got %d. Returning EINVAL.", CurrentVersion, h.Version)
		return nil, syscall.EINVAL
	}

	return &h, nil
}
