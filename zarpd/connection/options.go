package connection

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
)

func (p Profile) hasTransportOptions() bool {
	return p.XHTTPMode != nil || p.XHTTPExtra != nil || p.XHTTPPadding != nil || p.ECHConfig != nil ||
		len(p.CertificatePins) != 0 || len(p.CertificateNames) != 0 || p.SpiderX != nil || p.MLDSAVerify != nil
}
func (p Profile) transportOptionIdentity() []string {
	fields := []string{"server-transport-options-v1", pointerValue(p.XHTTPMode), pointerValue(p.XHTTPExtra), pointerValue(p.XHTTPPadding), pointerValue(p.ECHConfig), strconv.Itoa(len(p.CertificatePins))}
	fields = append(fields, p.CertificatePins...)
	fields = append(fields, strconv.Itoa(len(p.CertificateNames)))
	fields = append(fields, p.CertificateNames...)
	return append(fields, pointerValue(p.SpiderX), pointerValue(p.MLDSAVerify))
}

func (p Profile) validateTransportOptions() error {
	if p.Transport != "xhttp" {
		if p.XHTTPMode != nil || p.XHTTPExtra != nil || p.XHTTPPadding != nil {
			return Error{"modeOptions"}
		}
		if len(p.CertificatePins) != 0 || len(p.CertificateNames) != 0 || p.SpiderX != nil || p.MLDSAVerify != nil {
			return Error{"parameters"}
		}
	} else {
		if !(p.Protocol == "vless" || p.Protocol == "trojan") || p.Security == "none" {
			return Error{"transport"}
		}
		if p.XHTTPMode != nil && !xhttpMode(*p.XHTTPMode) {
			return Error{"modeOptions"}
		}
		if p.XHTTPPadding != nil {
			if _, ok := optionRange(*p.XHTTPPadding, 65535); !ok {
				return Error{"padding"}
			}
		}
		if p.XHTTPPadding != nil && p.XHTTPExtra != nil {
			return Error{"padding"}
		}
		if p.XHTTPExtra != nil {
			data := []byte(*p.XHTTPExtra)
			var extra map[string]any
			if ValidateDocumentJSON(data, 8192) != nil || json.Unmarshal(data, &extra) != nil || extra == nil || !p.validExtra(extra, true) {
				return Error{"extra"}
			}
		}
	}
	if p.ECHConfig != nil {
		raw, err := base64.StdEncoding.DecodeString(*p.ECHConfig)
		if p.Security != "tls" || len(*p.ECHConfig) > 4096 || err != nil || len(raw) < 6 || int(raw[0])*256+int(raw[1]) != len(raw)-2 {
			return Error{"ech"}
		}
	}
	if len(p.CertificatePins) > 8 || len(p.CertificatePins) != 0 && p.Security != "tls" {
		return Error{"certificatePin"}
	}
	for _, value := range p.CertificatePins {
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != 32 || strings.ToLower(value) != value {
			return Error{"certificatePin"}
		}
	}
	if len(p.CertificateNames) > 8 || len(p.CertificateNames) != 0 && p.Security != "tls" {
		return Error{"certificateName"}
	}
	for _, value := range p.CertificateNames {
		if !host(strings.TrimPrefix(value, "*.")) {
			return Error{"certificateName"}
		}
	}
	if p.SpiderX != nil && (p.Security != "reality" || !strings.HasPrefix(*p.SpiderX, "/") || !text(*p.SpiderX, 256)) {
		return Error{"parameters"}
	}
	if p.MLDSAVerify != nil {
		raw, err := base64.RawURLEncoding.DecodeString(*p.MLDSAVerify)
		if p.Security != "reality" || len(*p.MLDSAVerify) != 2603 || err != nil || len(raw) != 1952 {
			return Error{"publicKey"}
		}
	}
	return nil
}
func xhttpMode(value string) bool {
	return contains([]string{"auto", "packet-up", "stream-up", "stream-one"}, value)
}
func optionInteger(value any, maximum int) (int, bool) {
	n, ok := value.(float64)
	if !ok || n < 0 || n > float64(maximum) || n != float64(int(n)) {
		return 0, false
	}
	return int(n), true
}
func optionRange(value any, maximum int) (int, bool) {
	if s, ok := value.(string); ok {
		parts := strings.Split(s, "-")
		if len(parts) < 1 || len(parts) > 2 {
			return 0, false
		}
		values := make([]int, len(parts))
		for i, part := range parts {
			if part == "" {
				return 0, false
			}
			for _, b := range []byte(part) {
				if b < '0' || b > '9' {
					return 0, false
				}
			}
			n, err := strconv.Atoi(part)
			if err != nil || n > maximum {
				return 0, false
			}
			values[i] = n
		}
		return values[len(values)-1], values[0] <= values[len(values)-1]
	}
	return optionInteger(value, maximum)
}
func (p Profile) validExtra(extra map[string]any, download bool) bool {
	ranges := map[string]int{"xPaddingBytes": 65535, "uplinkChunkSize": 1048576, "scMaxEachPostBytes": 16777216, "scMinPostsIntervalMs": 60000, "scStreamUpServerSecs": 3600, "sessionIDLength": 256}
	for key, value := range extra {
		if maximum, ok := ranges[key]; ok {
			if _, ok = optionRange(value, maximum); !ok {
				return false
			}
			continue
		}
		if contains([]string{"xPaddingKey", "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod", "uplinkHTTPMethod", "sessionIDPlacement", "sessionIDKey", "sessionIDTable", "seqPlacement", "seqKey", "uplinkDataPlacement", "uplinkDataKey"}, key) {
			s, ok := value.(string)
			if !ok || !text(s, 256) {
				return false
			}
			continue
		}
		if contains([]string{"xPaddingObfsMode", "noGRPCHeader", "noSSEHeader"}, key) {
			if _, ok := value.(bool); !ok {
				return false
			}
			continue
		}
		switch key {
		case "headers":
			headers, ok := value.(map[string]any)
			if !ok || len(headers) > 32 {
				return false
			}
			for name, value := range headers {
				if name == "" || len(name) > 64 || strings.EqualFold(name, "host") {
					return false
				}
				for _, b := range []byte(name) {
					if b < 33 || b > 126 || strings.ContainsRune("()<>@,;:\\\"/[]?={} ", rune(b)) {
						return false
					}
				}
				s, ok := value.(string)
				if !ok || !text(s, 1024) {
					return false
				}
			}
		case "scMaxBufferedPosts":
			if _, ok := optionInteger(value, 64); !ok {
				return false
			}
		case "serverMaxHeaderBytes":
			if _, ok := optionInteger(value, 1048576); !ok {
				return false
			}
		case "xmux":
			mux, ok := value.(map[string]any)
			if !ok {
				return false
			}
			if mux["maxConcurrency"] != nil && mux["maxConnections"] != nil {
				return false
			}
			limits := map[string]int{"maxConcurrency": 128, "maxConnections": 32, "cMaxReuseTimes": 10000, "hMaxRequestTimes": 10000, "hMaxReusableSecs": 86400, "hKeepAlivePeriod": 3600}
			for key, value := range mux {
				maximum, ok := limits[key]
				if !ok {
					return false
				}
				if key == "hKeepAlivePeriod" {
					if _, ok := optionInteger(value, maximum); !ok {
						return false
					}
				} else if _, ok := optionRange(value, maximum); !ok {
					return false
				}
			}
		case "downloadSettings":
			settings, ok := value.(map[string]any)
			if !ok || !download || !p.validDownload(settings) {
				return false
			}
		default:
			return false
		}
	}
	postSize, posts := 1048576, 30
	if value, ok := extra["scMaxEachPostBytes"]; ok {
		postSize, _ = optionRange(value, 16777216)
	}
	if value, ok := extra["scMaxBufferedPosts"]; ok {
		posts, _ = optionInteger(value, 64)
	}
	return postSize*posts <= 67108864
}
func (p Profile) validDownload(settings map[string]any) bool {
	for key, value := range settings {
		switch key {
		case "address":
			s, ok := value.(string)
			if !ok || !strings.EqualFold(s, p.Host) {
				return false
			}
		case "port":
			n, ok := optionInteger(value, 65535)
			if !ok || n != p.Port {
				return false
			}
		case "network":
			if value != "xhttp" {
				return false
			}
		case "security":
			if value != p.Security {
				return false
			}
		case "tlsSettings", "realitySettings":
			if key != p.Security+"Settings" {
				return false
			}
			tls, ok := value.(map[string]any)
			if !ok {
				return false
			}
			for key, value := range tls {
				switch key {
				case "serverName":
					name := p.Host
					if p.ServerName != nil {
						name = *p.ServerName
					}
					if value != name {
						return false
					}
				case "alpn":
					values, ok := value.([]any)
					if !ok || len(values) != len(p.ALPN) {
						return false
					}
					for i, value := range values {
						if value != p.ALPN[i] {
							return false
						}
					}
				default:
					return false
				}
			}
		case "xhttpSettings":
			original, ok := value.(map[string]any)
			if !ok {
				return false
			}
			xhttp := make(map[string]any, len(original))
			for k, v := range original {
				xhttp[k] = v
			}
			if value, exists := xhttp["mode"]; exists {
				s, ok := value.(string)
				if !ok || !xhttpMode(s) {
					return false
				}
				delete(xhttp, "mode")
			}
			if value, exists := xhttp["path"]; exists {
				s, ok := value.(string)
				if !ok || !strings.HasPrefix(s, "/") || !text(s, 2048) {
					return false
				}
				delete(xhttp, "path")
			}
			if value, exists := xhttp["host"]; exists {
				s, ok := value.(string)
				if !ok || !host(s) {
					return false
				}
				delete(xhttp, "host")
			}
			if value, exists := xhttp["extra"]; exists {
				delete(xhttp, "extra")
				extra, ok := value.(map[string]any)
				if !ok || len(xhttp) != 0 || !p.validExtra(extra, false) {
					return false
				}
			} else if !p.validExtra(xhttp, false) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
