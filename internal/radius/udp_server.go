package radius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
)

const (
	radiusAccessRequest      = 1
	radiusAccessAccept       = 2
	radiusAccessReject       = 3
	radiusAccountingRequest  = 4
	radiusAccountingResponse = 5

	attrUserName          = 1
	attrUserPassword      = 2
	attrCHAPPassword      = 3
	attrReplyMessage      = 18
	attrCHAPChallenge     = 60
	attrSessionTimeout    = 27
	attrVendorSpecific    = 26
	mikrotikVendorID      = 14988
	mikrotikRateLimitAttr = 8
)

type radiusPacket struct {
	Code          byte
	Identifier    byte
	Authenticator []byte
	Attributes    map[byte][][]byte
}

func (s *Service) StartUDPServers(authPort, acctPort int, defaultSecret string) {
	go s.serveUDP(authPort, defaultSecret, s.handleAccessPacket, "auth")
	go s.serveUDP(acctPort, defaultSecret, s.handleAccountingPacket, "accounting")
}

func (s *Service) serveUDP(port int, defaultSecret string, handler func(radiusPacket, *net.UDPAddr, string) ([]byte, error), label string) {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: port}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Printf("radius: %s listener failed on UDP %d: %v", label, port, err)
		return
	}
	defer conn.Close()
	log.Printf("radius: %s listening on UDP %d", label, port)

	buffer := make([]byte, 4096)
	for {
		n, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("radius: %s read failed: %v", label, err)
			continue
		}
		packet, err := parseRadiusPacket(buffer[:n])
		if err != nil {
			log.Printf("radius: invalid %s packet from %s: %v", label, remote, err)
			continue
		}
		secret := s.secretForNAS(remote.IP.String(), defaultSecret)
		response, err := handler(packet, remote, secret)
		if err != nil {
			log.Printf("radius: %s request from %s failed: %v", label, remote, err)
			continue
		}
		if _, err := conn.WriteToUDP(response, remote); err != nil {
			log.Printf("radius: %s response to %s failed: %v", label, remote, err)
		}
	}
}

func (s *Service) handleAccessPacket(packet radiusPacket, remote *net.UDPAddr, secret string) ([]byte, error) {
	if packet.Code != radiusAccessRequest {
		return nil, fmt.Errorf("unexpected packet code %d", packet.Code)
	}
	username := strings.TrimSpace(string(firstAttribute(packet, attrUserName)))
	if username == "" {
		return encodeRadiusResponse(packet, radiusAccessReject, secret, replyMessage("Missing voucher code.")), nil
	}
	if !s.passwordMatches(packet, secret, username) {
		log.Printf("radius: reject user=%s nas=%s reason=password", username, remote.IP)
		return encodeRadiusResponse(packet, radiusAccessReject, secret, replyMessage("Invalid voucher code.")), nil
	}

	voucher, plan, err := s.voucherPlan(username)
	if err != nil || !voucherUsable(voucher) {
		log.Printf("radius: reject user=%s nas=%s reason=voucher err=%v", username, remote.IP, err)
		return encodeRadiusResponse(packet, radiusAccessReject, secret, replyMessage("Invalid or expired voucher code.")), nil
	}

	attrs := [][]byte{
		uint32Attribute(attrSessionTimeout, uint32(max(plan.DurationMinutes, 1)*60)),
		mikrotikRateLimitAttribute(mikrotikRateLimit(plan.UploadSpeed, plan.DownloadSpeed)),
		replyMessage("Welcome to NobliFi WiFi."),
	}
	log.Printf("radius: accept user=%s nas=%s plan=%s", username, remote.IP, plan.Name)
	return encodeRadiusResponse(packet, radiusAccessAccept, secret, attrs...), nil
}

func (s *Service) handleAccountingPacket(packet radiusPacket, _ *net.UDPAddr, secret string) ([]byte, error) {
	if packet.Code != radiusAccountingRequest {
		return nil, fmt.Errorf("unexpected packet code %d", packet.Code)
	}
	return encodeRadiusResponse(packet, radiusAccountingResponse, secret), nil
}

func (s *Service) secretForNAS(nasName, fallback string) string {
	var nas NAS
	if err := s.db.First(&nas, "nasname = ?", nasName).Error; err == nil && strings.TrimSpace(nas.Secret) != "" {
		return strings.TrimSpace(nas.Secret)
	}
	if strings.TrimSpace(fallback) == "" {
		return "noblifi"
	}
	return strings.TrimSpace(fallback)
}

func (s *Service) voucherPlan(code string) (vouchers.Voucher, plans.Plan, error) {
	var voucher vouchers.Voucher
	if err := s.db.First(&voucher, "code = ?", code).Error; err != nil {
		return voucher, plans.Plan{}, err
	}
	var plan plans.Plan
	if err := s.db.First(&plan, "id = ?", voucher.PlanID).Error; err != nil {
		return voucher, plan, err
	}
	if !plan.IsActive {
		return voucher, plan, errors.New("plan is inactive")
	}
	return voucher, plan, nil
}

func voucherUsable(voucher vouchers.Voucher) bool {
	if voucher.Status != "unused" && voucher.Status != "active" {
		return false
	}
	return voucher.ExpiresAt == nil || voucher.ExpiresAt.After(time.Now())
}

func (s *Service) passwordMatches(packet radiusPacket, secret, expected string) bool {
	if password := firstAttribute(packet, attrUserPassword); len(password) > 0 {
		return decryptUserPassword(password, secret, packet.Authenticator) == expected
	}
	if chap := firstAttribute(packet, attrCHAPPassword); len(chap) == 17 {
		challenge := firstAttribute(packet, attrCHAPChallenge)
		if len(challenge) == 0 {
			challenge = packet.Authenticator
		}
		sum := md5.Sum(append(append([]byte{chap[0]}, []byte(expected)...), challenge...))
		return bytes.Equal(chap[1:], sum[:])
	}
	return false
}

func parseRadiusPacket(data []byte) (radiusPacket, error) {
	if len(data) < 20 {
		return radiusPacket{}, errors.New("packet too short")
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < 20 || length > len(data) {
		return radiusPacket{}, errors.New("invalid packet length")
	}
	packet := radiusPacket{
		Code:          data[0],
		Identifier:    data[1],
		Authenticator: append([]byte(nil), data[4:20]...),
		Attributes:    map[byte][][]byte{},
	}
	for offset := 20; offset < length; {
		if offset+2 > length {
			return radiusPacket{}, errors.New("truncated attribute")
		}
		attrType := data[offset]
		attrLen := int(data[offset+1])
		if attrLen < 2 || offset+attrLen > length {
			return radiusPacket{}, errors.New("invalid attribute length")
		}
		packet.Attributes[attrType] = append(packet.Attributes[attrType], append([]byte(nil), data[offset+2:offset+attrLen]...))
		offset += attrLen
	}
	return packet, nil
}

func encodeRadiusResponse(request radiusPacket, code byte, secret string, attrs ...[]byte) []byte {
	length := 20
	for _, attr := range attrs {
		length += len(attr)
	}
	response := make([]byte, 20, length)
	response[0] = code
	response[1] = request.Identifier
	binary.BigEndian.PutUint16(response[2:4], uint16(length))
	copy(response[4:20], request.Authenticator)
	for _, attr := range attrs {
		response = append(response, attr...)
	}
	sumInput := append([]byte(nil), response...)
	sumInput = append(sumInput, []byte(secret)...)
	sum := md5.Sum(sumInput)
	copy(response[4:20], sum[:])
	return response
}

func firstAttribute(packet radiusPacket, attrType byte) []byte {
	values := packet.Attributes[attrType]
	if len(values) == 0 {
		return nil
	}
	return values[0]
}

func decryptUserPassword(ciphertext []byte, secret string, authenticator []byte) string {
	if len(ciphertext) == 0 || len(ciphertext)%16 != 0 {
		return ""
	}
	plain := make([]byte, 0, len(ciphertext))
	previous := authenticator
	for offset := 0; offset < len(ciphertext); offset += 16 {
		block := ciphertext[offset : offset+16]
		sum := md5.Sum(append([]byte(secret), previous...))
		for i := 0; i < 16; i++ {
			plain = append(plain, block[i]^sum[i])
		}
		previous = block
	}
	return string(bytes.TrimRight(plain, "\x00"))
}

func replyMessage(message string) []byte {
	return stringAttribute(attrReplyMessage, message)
}

func stringAttribute(attrType byte, value string) []byte {
	raw := []byte(value)
	if len(raw) > 253 {
		raw = raw[:253]
	}
	return append([]byte{attrType, byte(len(raw) + 2)}, raw...)
}

func uint32Attribute(attrType byte, value uint32) []byte {
	attr := []byte{attrType, 6, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(attr[2:6], value)
	return attr
}

func mikrotikRateLimitAttribute(value string) []byte {
	valueAttr := []byte(value)
	if len(valueAttr) > 247 {
		valueAttr = valueAttr[:247]
	}
	vsa := make([]byte, 0, len(valueAttr)+8)
	vsa = append(vsa, attrVendorSpecific, byte(len(valueAttr)+8))
	vendor := make([]byte, 4)
	binary.BigEndian.PutUint32(vendor, mikrotikVendorID)
	vsa = append(vsa, vendor...)
	vsa = append(vsa, mikrotikRateLimitAttr, byte(len(valueAttr)+2))
	vsa = append(vsa, valueAttr...)
	return vsa
}
