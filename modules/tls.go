package modules

import (
	"encoding/hex"
	"github.com/Positive-Engineer/zgrab2"
	log "github.com/sirupsen/logrus"
	"strconv"
)

type TLSFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	FilterFingerprintMD5    string `long:"filter-md5" description:"filter results with fingerprint md5."`
	FilterFingerprintSHA1   string `long:"filter-sha1" description:"filter results with fingerprint sha1."`
	FilterFingerprintSHA256 string `long:"filter-sha256" description:"filter results with fingerprint sha256."`
	FilterFingerprintSerial string `long:"filter-serialnumber" description:"filter results with fingerprint serial number in dec."`
}

type TLSModule struct {
}

type TLSScanner struct {
	config *TLSFlags
}

func init() {
	var tlsModule TLSModule
	_, err := zgrab2.AddCommand("tls", "TLS Banner Grab", tlsModule.Description(), 443, &tlsModule)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *TLSModule) NewFlags() interface{} {
	return new(TLSFlags)
}

func (m *TLSModule) NewScanner() zgrab2.Scanner {
	return new(TLSScanner)
}

// Description returns an overview of this module.
func (m *TLSModule) Description() string {
	return "Perform a TLS handshake"
}

func (f *TLSFlags) Validate(args []string) error {
	return nil
}

func (f *TLSFlags) Help() string {
	return ""
}

func (s *TLSScanner) Init(flags zgrab2.ScanFlags) error {
	f, ok := flags.(*TLSFlags)
	if !ok {
		return zgrab2.ErrMismatchedFlags
	}
	s.config = f
	return nil
}

func (s *TLSScanner) GetName() string {
	return s.config.Name
}

func (s *TLSScanner) GetTrigger() string {
	return s.config.Trigger
}

func (s *TLSScanner) InitPerSender(senderID int) error {
	return nil
}

// Scan opens a TCP connection to the target (default port 443), then performs
// a TLS handshake. If the handshake gets past the ServerHello stage, the
// handshake log is returned (along with any other TLS-related logs, such as
// heartbleed, if enabled).
func (s *TLSScanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := t.OpenTLS(&s.config.BaseFlags, &s.config.TLSFlags)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		if conn != nil {
			if log := conn.GetLog(); log != nil {
				if log.HandshakeLog.ServerHello != nil {
					// If we got far enough to get a valid ServerHello, then
					// consider it to be a positive TLS detection.
					return zgrab2.TryGetScanStatus(err), log, err
				}
				// Otherwise, detection failed.
			}
		}
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	LogDataTLS := conn.GetLog()
	switch {
	case len(s.config.FilterFingerprintMD5) > 0:
		_cert_md5 := LogDataTLS.HandshakeLog.ServerCertificates.Certificate.Parsed.FingerprintMD5
		cert_md5 := hex.EncodeToString(_cert_md5[:])
		filter_md5 := s.config.FilterFingerprintMD5
		if cert_md5 == filter_md5 {
			return zgrab2.SCAN_SUCCESS, LogDataTLS, nil
		}
		if LogDataTLS.HandshakeLog.ServerCertificates.Chain != nil {
			for _, value := range LogDataTLS.HandshakeLog.ServerCertificates.Chain {
				_cert_md5 := value.Parsed.FingerprintMD5
				cert_md5 := hex.EncodeToString(_cert_md5[:])
				if cert_md5 == filter_md5 {
					return zgrab2.SCAN_SUCCESS, LogDataTLS, nil
				}
			}
		}
		return zgrab2.SCAN_SUCCESS_NOTCONTAIN, nil, nil
	case len(s.config.FilterFingerprintSHA1) > 0:
		_cert_sha1 := LogDataTLS.HandshakeLog.ServerCertificates.Certificate.Parsed.FingerprintSHA1
		cert_sha1 := hex.EncodeToString(_cert_sha1[:])
		filter_sha1 := s.config.FilterFingerprintSHA1
		if cert_sha1 == filter_sha1 {
			return zgrab2.SCAN_SUCCESS, LogDataTLS, nil
		}
		if LogDataTLS.HandshakeLog.ServerCertificates.Chain != nil {
			for _, value := range LogDataTLS.HandshakeLog.ServerCertificates.Chain {
				_cert_sha1 := value.Parsed.FingerprintSHA1
				cert_sha1 := hex.EncodeToString(_cert_sha1[:])
				if cert_sha1 == filter_sha1 {
					return zgrab2.SCAN_SUCCESS, LogDataTLS, nil
				}
			}
		}
		return zgrab2.SCAN_SUCCESS_NOTCONTAIN, nil, nil
	case len(s.config.FilterFingerprintSHA256) > 0:
		_cert_sha256 := LogDataTLS.HandshakeLog.ServerCertificates.Certificate.Parsed.FingerprintSHA256
		cert_sha256 := hex.EncodeToString(_cert_sha256[:])
		filter_sha256 := s.config.FilterFingerprintSHA256
		if cert_sha256 == filter_sha256 {
			return zgrab2.SCAN_SUCCESS, LogDataTLS, nil
		}
		if LogDataTLS.HandshakeLog.ServerCertificates.Chain != nil {
			for _, value := range LogDataTLS.HandshakeLog.ServerCertificates.Chain {
				_cert_sha256 := value.Parsed.FingerprintSHA256
				cert_sha256 := hex.EncodeToString(_cert_sha256[:])
				if cert_sha256 == filter_sha256 {
					return zgrab2.SCAN_SUCCESS, LogDataTLS, nil
				}
			}
		}
		return zgrab2.SCAN_SUCCESS_NOTCONTAIN, nil, nil
	case len(s.config.FilterFingerprintSerial) > 0:
		_cert_serial := LogDataTLS.HandshakeLog.ServerCertificates.Certificate.Parsed.SerialNumber.Uint64()
		cert_serial := strconv.FormatUint(_cert_serial, 10)
		filter_serialnumber := s.config.FilterFingerprintSerial
		if filter_serialnumber == cert_serial {
			return zgrab2.SCAN_SUCCESS, LogDataTLS, nil
		}
		if LogDataTLS.HandshakeLog.ServerCertificates.Chain != nil {
			for _, value := range LogDataTLS.HandshakeLog.ServerCertificates.Chain {
				_cert_serial := value.Parsed.SerialNumber.Uint64()
				cert_serial := strconv.FormatUint(_cert_serial, 10)
				if filter_serialnumber == cert_serial {
					return zgrab2.SCAN_SUCCESS, LogDataTLS, nil
				}
			}
		}
		return zgrab2.SCAN_SUCCESS_NOTCONTAIN, nil, nil
	}
	return zgrab2.SCAN_SUCCESS, LogDataTLS, nil
}

// Protocol returns the protocol identifer for the scanner.
func (s *TLSScanner) Protocol() string {
	return "tls"
}
