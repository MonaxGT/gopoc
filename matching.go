package gopoc

import (
	"net/http"
	"regexp"
	"strings"
)

func matchRe(config *Template, respBody []byte) bool {
	r, _ := regexp.Compile(config.Parameter.Find_regex)
	return r.Match([]byte(respBody))
}

func matchStr(config *Template, respBody []byte) bool {
	return strings.Contains(string(respBody), config.Parameter.Find)
}

func matchHeader(config *Template, Headers *http.Header) bool {
	for k, v := range config.Parameter.Find_in_headers {
		if Headers.Get(k) == v {
			continue
		} else {
			return false
		}
	}
	return true
}
