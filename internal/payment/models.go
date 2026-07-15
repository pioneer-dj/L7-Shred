package payment

type LavaConfig struct {
	APIKey        string
	WebhookSecret string
	ProductID     string
	BaseURL       string
}

type LavaCreateInvoiceResponse struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	PaymentURL string `json:"paymentUrl"`
	AmountTotal struct {
		Currency string  `json:"currency"`
		Amount   float64 `json:"amount"`
	} `json:"amountTotal"`
}

type WebhookPayload struct {
	EventType string `json:"eventType"`
	Data      struct {
		InvoiceID      string  `json:"invoiceId"`
		SubscriptionID string  `json:"subscriptionId,omitempty"`
		ProductID      string  `json:"productId"`
		Amount         float64 `json:"amount"`
		Currency       string  `json:"currency"`
		Status         string  `json:"status"`
		BuyerEmail     string  `json:"buyerEmail"`
		BuyerID        string  `json:"buyerId,omitempty"`
	} `json:"data"`
}