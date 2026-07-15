package payment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const LavaBaseURL = "https://gate.lava.top"

type LavaClient struct {
	apiKey     string
	productID  string
	httpClient *http.Client
}

func NewLavaClient(apiKey, productID string) *LavaClient {
	return &LavaClient{
		apiKey:    apiKey,
		productID: productID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (l *LavaClient) CreateInvoice(email string) (*LavaCreateInvoiceResponse, error) {
	url := LavaBaseURL + "/api/v3/invoice"

	reqBody := map[string]interface{}{
		"email":    email,
		"offerId":  l.productID,
		"currency": "USD",
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	fmt.Printf("[Lava] Request: %s\n", string(jsonData))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Api-Key", l.apiKey)

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	fmt.Printf("[Lava] Response status: %d\n", resp.StatusCode)
	fmt.Printf("[Lava] Response body: %s\n", string(body))

	var result LavaCreateInvoiceResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, fmt.Errorf("lava API error: status=%d, body=%s", resp.StatusCode, string(body))
	}

	return &result, nil
}