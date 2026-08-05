package mikrotik

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	Address  string
	Port     int
	Username string
	Password string
	Timeout  time.Duration
}

func NewClient(address, username, password string) *Client {
	return &Client{
		Address:  address,
		Port:     8728,
		Username: username,
		Password: password,
		Timeout:  8 * time.Second,
	}
}

func (c *Client) WithPort(port int) *Client {
	if port > 0 {
		c.Port = port
	}
	return c
}

func (c *Client) DialAndLogin() (*Conn, error) {
	if strings.TrimSpace(c.Address) == "" {
		return nil, errors.New("router address is required")
	}
	port := c.Port
	if port <= 0 {
		port = 8728
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.Address, strconv.Itoa(port)), timeout)
	if err != nil {
		return nil, err
	}
	api := &Conn{
		conn: conn,
		rw:   bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
	}
	if err := api.Login(c.Username, c.Password); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return api, nil
}

func (c *Client) Command(path string, args map[string]string) ([]map[string]string, error) {
	conn, err := c.DialAndLogin()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.Command(path, args)
}

func (c *Client) Apply(script string) error {
	_, err := c.Command("/system/script/run", map[string]string{"=.id": script})
	return err
}

type Conn struct {
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (c *Conn) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Conn) Login(username, password string) error {
	replies, err := c.Command("/login", map[string]string{
		"=name":     username,
		"=password": password,
	})
	if err == nil && len(replies) >= 0 {
		return nil
	}

	replies, challengeErr := c.rawCommand("/login", nil)
	if challengeErr != nil {
		return err
	}
	var challenge string
	for _, reply := range replies {
		if value := reply["=ret"]; value != "" {
			challenge = value
			break
		}
	}
	if challenge == "" {
		return err
	}
	decoded, decodeErr := hex.DecodeString(challenge)
	if decodeErr != nil {
		return err
	}
	sum := md5.Sum(append(append([]byte{0}, []byte(password)...), decoded...))
	response := "00" + hex.EncodeToString(sum[:])
	_, err = c.Command("/login", map[string]string{
		"=name":     username,
		"=response": response,
	})
	return err
}

func (c *Conn) Command(path string, args map[string]string) ([]map[string]string, error) {
	return c.rawCommand(path, args)
}

func (c *Conn) rawCommand(path string, args map[string]string) ([]map[string]string, error) {
	if err := c.writeSentence(path, args); err != nil {
		return nil, err
	}
	var rows []map[string]string
	for {
		words, err := c.readSentence()
		if err != nil {
			return nil, err
		}
		if len(words) == 0 {
			continue
		}
		switch words[0] {
		case "!done":
			return rows, nil
		case "!re":
			rows = append(rows, wordsToMap(words[1:]))
		case "!trap", "!fatal":
			values := wordsToMap(words[1:])
			message := values["=message"]
			if message == "" {
				message = words[0]
			}
			return rows, errors.New(message)
		}
	}
}

func (c *Conn) writeSentence(path string, args map[string]string) error {
	if err := c.writeWord(path); err != nil {
		return err
	}
	for key, value := range args {
		if err := c.writeWord(key + "=" + value); err != nil {
			return err
		}
	}
	if err := c.writeWord(""); err != nil {
		return err
	}
	return c.rw.Flush()
}

func (c *Conn) writeWord(word string) error {
	if err := writeLength(c.rw, len(word)); err != nil {
		return err
	}
	if word == "" {
		return nil
	}
	_, err := c.rw.WriteString(word)
	return err
}

func (c *Conn) readSentence() ([]string, error) {
	words := []string{}
	for {
		length, err := readLength(c.rw)
		if err != nil {
			return nil, err
		}
		if length == 0 {
			return words, nil
		}
		buffer := make([]byte, length)
		if _, err := io.ReadFull(c.rw, buffer); err != nil {
			return nil, err
		}
		words = append(words, string(buffer))
	}
}

func writeLength(w io.Writer, length int) error {
	switch {
	case length < 0x80:
		_, err := w.Write([]byte{byte(length)})
		return err
	case length < 0x4000:
		_, err := w.Write([]byte{byte(length>>8) | 0x80, byte(length)})
		return err
	case length < 0x200000:
		_, err := w.Write([]byte{byte(length>>16) | 0xC0, byte(length >> 8), byte(length)})
		return err
	case length < 0x10000000:
		_, err := w.Write([]byte{byte(length>>24) | 0xE0, byte(length >> 16), byte(length >> 8), byte(length)})
		return err
	default:
		return fmt.Errorf("RouterOS API word is too long")
	}
}

func readLength(r io.Reader) (int, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	value := int(first[0])
	switch {
	case value&0x80 == 0:
		return value, nil
	case value&0xC0 == 0x80:
		var rest [1]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return ((value & ^0xC0) << 8) + int(rest[0]), nil
	case value&0xE0 == 0xC0:
		var rest [2]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return ((value & ^0xE0) << 16) + int(rest[0])<<8 + int(rest[1]), nil
	case value&0xF0 == 0xE0:
		var rest [3]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return ((value & ^0xF0) << 24) + int(rest[0])<<16 + int(rest[1])<<8 + int(rest[2]), nil
	default:
		var rest [4]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return int(rest[0])<<24 + int(rest[1])<<16 + int(rest[2])<<8 + int(rest[3]), nil
	}
}

func wordsToMap(words []string) map[string]string {
	result := map[string]string{}
	for _, word := range words {
		if !strings.HasPrefix(word, "=") {
			continue
		}
		key, value, ok := strings.Cut(word[1:], "=")
		if !ok {
			continue
		}
		result["="+key] = value
	}
	return result
}
