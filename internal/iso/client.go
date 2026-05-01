package iso

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultTimeout = 30 * time.Second

var defaultClient = &http.Client{Timeout: defaultTimeout}

var insecureClient *http.Client

func init() {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	insecureClient = &http.Client{Transport: transport, Timeout: defaultTimeout}
}

type Client struct {
	url          string
	clientID     string
	clientSecret string
	accessToken  string
	Verbose      bool
	Insecure     bool
}

func NewClient(senhaseguraUrl string, clientID string, clientSecret string, verbose bool, insecure bool) (Client, error) {
	u := strings.TrimSpace(senhaseguraUrl)
	if u == "" {
		return Client{}, fmt.Errorf("URL cannot be null")
	}

	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return Client{}, fmt.Errorf("Client ID cannot be null")
	}

	clientSecret = strings.TrimSpace(clientSecret)
	if clientSecret == "" {
		return Client{}, fmt.Errorf("Client Secret cannot be null")
	}

	return Client{
		url:          u,
		clientID:     clientID,
		clientSecret: clientSecret,
		Verbose:      verbose,
		Insecure:     insecure,
	}, nil
}

func (c *Client) DefineNewCredentials(clientID string, clientSecret string) error {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return fmt.Errorf("Client ID cannot be null")
	}

	clientSecret = strings.TrimSpace(clientSecret)
	if clientSecret == "" {
		return fmt.Errorf("Client Secret cannot be null")
	}

	c.clientID = clientID
	c.clientSecret = clientSecret
	return nil
}

func (c *Client) Authenticate() error {
	c.V("Trying to authenticate on senhasegura DevSecOps API\n")

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)

	var oauth2Resp Oauth2Response
	if err := c.Post("/iso/oauth2/token", data, &oauth2Resp); err != nil {
		return fmt.Errorf("error trying to authenticate: %w", err)
	}

	c.accessToken = "Bearer " + oauth2Resp.GetAccessToken()
	c.V("Authenticated successfully\n")
	return nil
}

func (c *Client) V(format string, a ...interface{}) {
	if c.Verbose {
		fmt.Printf(format, a...)
	}
}

func (c Client) Post(resource string, data url.Values, responseObj ResponseInterface) error {
	return c.call(http.MethodPost, resource, data, responseObj)
}

func (c Client) Get(resource string, data url.Values, responseObj ResponseInterface) error {
	return c.call(http.MethodGet, resource, data, responseObj)
}

func (c Client) call(method string, resource string, data url.Values, responseObj ResponseInterface) error {
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	if c.accessToken != "" {
		headers["Authorization"] = c.accessToken
	}

	responseData, err := DoRequest(c.url, resource, data, headers, method, c.Insecure)
	if err != nil {
		return err
	}

	if err = responseObj.Unmarshal(responseData); err != nil {
		return err
	}

	return responseObj.Validate()
}

func DoRequest(host string, resource string, data url.Values, headers map[string]string, method string, insecure bool) ([]byte, error) {
	u, err := url.ParseRequestURI(host)
	if err != nil {
		return nil, err
	}
	u.Path = resource

	r, err := http.NewRequest(method, u.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		r.Header.Add(k, v)
	}

	client := defaultClient
	if insecure {
		client = insecureClient
	}

	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}
