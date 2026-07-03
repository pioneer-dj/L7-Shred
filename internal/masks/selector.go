package masks

import (
	"strings"
)

type MaskSelector struct {
	domainMap map[string]string
}

func NewMaskSelector() *MaskSelector {
	return &MaskSelector{
		domainMap: map[string]string{
			"youtube.com":    "tls",
			"google.com":     "tls",
			"gmail.com":      "tls",
			"drive.google":   "tls",
			"whatsapp.com":   "webrtc",
			"instagram.com":  "quic",
			"facebook.com":   "quic",
			"twitter.com":    "quic",
			"discord.com":    "webrtc",
			"spotify.com":    "quic",
			"netflix.com":    "webrtc",
			"twitch.tv":      "webrtc",
			"vk.com":         "vk",
			"rutube.ru":      "rutube",
			"yandex.ru":      "yandex",
			"ya.ru":          "yandex",
			"ozon.ru":        "ozon",
			"wildberries.ru": "wildberries",
			"sberbank.ru":    "sberid",
			"sberid.ru":      "sberid",
			"gosuslugi.ru":   "gosuslugi",
			"telegram.org":   "vk",
			"t.me":           "vk",
			"default":        "webrtc",
		},
	}
}

func (ms *MaskSelector) Select(domain string) string {
	domain = strings.ToLower(domain)

	for pattern, mask := range ms.domainMap {
		if strings.Contains(domain, pattern) {
			return mask
		}
	}

	return ms.domainMap["default"]
}

func (ms *MaskSelector) SelectByIP(ip string) string {
	return ms.domainMap["default"]
}
