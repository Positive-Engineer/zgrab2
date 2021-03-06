// Package banner provides simple banner grab and matching implementation of the zgrab2.Module.
// It sends a customizble probe (default to "\n") and filters the results based on custom regexp (--pattern)

package banner

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/Positive-Engineer/zgrab2"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	Probe    string `long:"probe" default:"" description:"Probe to send to the server. Use triple slashes to escape, for example \\\\\\n is literal \\n" `
	Pattern  string `long:"pattern" description:"Pattern to match, must be valid regexp."`
	MaxTries int    `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up."`
	// indicates that the client should do a TLS handshake immediately after connecting.
	UseTLS               bool   `long:"use-tls" description:"client should do a TLS handshake immediately after connecting"`
	OnlyBASE64           bool   `long:"only-base64" description:"Output banner response from host only in base64."`
	ProbeBASE64          string `long:"single-payload" description:"Probe to send to the server, in base64."`
	SingleContains       string `long:"single-contain" description:"search bytes in banner, set in base64."`
	SingleContainsString string `long:"single-contain-string" default:"" description:"search substring in banner, set in string."`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	regex  *regexp.Regexp
	probe  []byte
}

type Results struct {
	Banner       string `json:"banner,omitempty"`
	Length       int    `json:"length,omitempty"`
	BannerBase64 string `json:"banner_base64,omitempty"`
	// TLSLog is the standard TLS log, if --use-tls is enabled.
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("banner", "Banner", module.Description(), 80, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "banner"
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(args []string) error {
	return nil
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Fetch a raw banner by sending a static probe and checking the result against a regular expression"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.regex = regexp.MustCompile(scanner.config.Pattern)

	if len(scanner.config.Probe) > 0 {
		probe, err := strconv.Unquote(fmt.Sprintf(`"%s"`, scanner.config.Probe))
		if err != nil {
			panic("Probe error")
		}
		scanner.probe = []byte(probe)
	} else if len(scanner.config.ProbeBASE64) > 0 {
		probe, err := base64.StdEncoding.DecodeString(scanner.config.ProbeBASE64)
		if err != nil {
			panic("Probe(BASE64) error")
		}
		scanner.probe = probe
	}

	return nil
}

var NoMatchError = errors.New("pattern did not match")

type Connection struct {
	Conn net.Conn
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	try := 0
	var (
		c       net.Conn
		err     error
		readerr error
	)
	for try < scanner.config.MaxTries {
		try += 1
		c, err = target.Open(&scanner.config.BaseFlags)
		if err != nil {
			continue
		}
		break
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer c.Close()

	result := &Results{}
	if scanner.config.UseTLS {
		tlsConn, err := scanner.config.TLSFlags.GetTLSConnection(c)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}
		result.TLSLog = tlsConn.GetLog()
		if err := tlsConn.Handshake(); err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		c = tlsConn
	}
	conn := Connection{Conn: c}
	var ret []byte
	try = 0
	err = nil
	for try < scanner.config.MaxTries {
		try += 1
		if len(scanner.probe) > 0 {
			_, err = conn.Conn.Write(scanner.probe)
		}
		ret, readerr = zgrab2.ReadAvailable(conn.Conn)
		if err != nil {
			continue
		}
		if readerr != io.EOF && readerr != nil {
			continue
		}
		break
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if readerr != io.EOF && readerr != nil {
		return zgrab2.TryGetScanStatus(readerr), nil, readerr
	}
	banner_base64 := base64.StdEncoding.EncodeToString(ret)
	banner_str := ""
	if !(scanner.config.OnlyBASE64) {
		banner_str = string(ret)
	}
	result.Banner = banner_str
	result.Length = len(ret)
	result.BannerBase64 = banner_base64

	if len(scanner.config.SingleContains) == 0 && len(scanner.config.SingleContainsString) == 0 {
		if scanner.regex.Match(ret) {
			return zgrab2.SCAN_SUCCESS, &result, nil
		}
	} else {
		check_bytes := []byte(scanner.config.SingleContainsString)
		var err_check_bytes error
		err_check_bytes = nil
		if len(scanner.config.SingleContains) > 0 {
			check_bytes, err_check_bytes = base64.StdEncoding.DecodeString(scanner.config.SingleContains)
		}
		if err_check_bytes == nil && len(check_bytes) > 0 {
			if bytes.Contains(ret, check_bytes) {
				return zgrab2.SCAN_SUCCESS, &result, nil
			} else {
				return zgrab2.SCAN_SUCCESS_NOTCONTAIN, nil, nil
			}
		}
	}
	return zgrab2.SCAN_PROTOCOL_ERROR, &result, NoMatchError

}
