package gopoc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
)

type TemplateList struct {
	List []Template `yaml:"poc"`
}
type Template struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Module      string `yaml:"module"`
	Parameter   struct {
		Author           string            `yaml:"author"`
		Cvss             float32           `yaml:"cvss"`
		Url              string            `yaml:"url"`
		Method           string            `yaml:"method"`
		Allow_redirects  bool              `yaml:"allow_redirects"`
		Find             string            `yaml:"find"`
		Find_in_headers  map[string]string `yaml:"find_in_headers"`
		Find_regex       string            `yaml:"find_regex"`
		Headers          map[string]string
		Headers_required map[string]string
		Body             map[string]string
		Delay_seconds    int    `yaml:"delay_seconds"`
		Cookies          string `yaml:"cookies"`
		Expect_resp_code int    `yaml:"expect_response_code"`
		Extract          struct {
			Csrf string `yaml:"csrf"`
		}
	}
	Time string `yaml:"time"`
	Case int    `yaml:"case"`
}

func request(client *http.Client, config *Template, data io.Reader, mode bool) ([]byte, http.Header, int) {
	req, err := http.NewRequest(config.Parameter.Method, config.Parameter.Url, data)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	// Add headers from yaml
	for key, value := range config.Parameter.Headers {
		req.Header.Add(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		errors.New("Error when sending request")
	}
	defer resp.Body.Close()
	respBody, _ := ioutil.ReadAll(resp.Body)
	if mode {
		fmt.Println("Request:")
		for key, value := range req.Header {
			fmt.Println(key, ":", value)
		}
		if config.Parameter.Method == "POST" {
			fmt.Println(req.Body)
		}
		fmt.Println("Respond:")
		for key, value := range resp.Header {
			fmt.Println(key, ":", value)
		}
		fmt.Println(string(respBody))
		fmt.Println("Request:")
		for key, value := range req.Header {
			fmt.Println(key, ":", value)
		}
		if config.Parameter.Method == "POST" {
			fmt.Println(req.Body)
		}
		fmt.Println("Respond:")
		for key, value := range resp.Header {
			fmt.Println(key, ":", value)
		}
		fmt.Println(string(respBody))
	}
	defer resp.Body.Close()
	return respBody, resp.Header, resp.StatusCode
}

func processorBody(config *Template, client *http.Client, jar *cookiejar.Jar, mode bool) bool {
	// Check content-type for json body. Add parameter from yaml with right encoding
	data := new(bytes.Buffer)
	value, ok := config.Parameter.Headers["Content-Type"]
	if ok && value == "application/json" {
		jsonValue, err := json.Marshal(config.Parameter.Body)
		if err != nil {
			log.Print(err)
			os.Exit(1)
		}
		data.Write(jsonValue)
	} else {
		data := new(bytes.Buffer)
		params := url.Values{}
		for key, value := range config.Parameter.Body {
			params.Set(key, value)
		}
		data.WriteString(params.Encode())
	}
	respBody, respHeader, statusCode := request(client, config, data, mode)
	if config.Parameter.Expect_resp_code != 0 {
		if config.Parameter.Expect_resp_code == statusCode {
			return true
		} else {
			return false
		}
	} else if config.Parameter.Find != "" {
		result := matchStr(config, respBody)
		return result
	} else if config.Parameter.Find_in_headers != nil {
		result := matchHeader(config, &respHeader)
		return result
	} else if config.Parameter.Find_regex != "" {
		result := matchRe(config, respBody)
		return result
	} else {
		log.Fatal("Need information for check. Please use find-like parameter or expect responce code")
		return false
	}
}

func handler(list *TemplateList, mode bool) bool {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	for i, x := range list.List {
		result := processorBody(&x, client, jar, mode)
		if result == false {
			if !mode {
				fmt.Printf("Step № %d not match \n", i)
			}
			return false
			break
		} else {
			continue
		}
	}
	return true
}

func Check(filename string, mode bool) bool {
	var config TemplateList
	source, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(source, &config)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	if mode {
		fmt.Printf("Loaded file: ")
		color.Cyan(filename)
		color.Red("Result %d", config.List[0].Case)
		fmt.Println(config.List[0].Name, config.List[1].Name)
		if config.List[0].Module == "metadata" {
			fmt.Printf("Author:%s\n", config.List[0].Parameter.Author)
			fmt.Printf("CVSS:%f\n", config.List[0].Parameter.Cvss)
		}
	}

	if config.List[0].Module == "metadata" {
		for i := len(config.List) - 1; i >= 0; i-- {
			application := config.List[i]
			if application.Module == "metadata" {
				config.List = append(config.List[:i],
					config.List[i+1:]...)
			}
		}

	} else {

	}
	return handler(&config, mode)
}
