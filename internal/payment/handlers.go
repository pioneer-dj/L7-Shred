package payment

import (
	"encoding/json"
	"net/http"

	"github.com/l7-shred/core/internal/database"
)

var (
	lavaAPIKey    = "l8anvElQqVPO0DRUgWuEhqTmC9fNqHncH1GVmcL8qxSwpW6xm3u9R8fmVBgNM7cF"
	lavaProductID = "147b08da-3284-4489-9901-9f914e93268d"
)

type CreateInvoiceRequest struct {
	Email string `json:"email"`
}

type CreateInvoiceResponse struct {
	Success    bool   `json:"success"`
	InvoiceID  string `json:"invoiceId,omitempty"`
	PaymentURL string `json:"paymentUrl,omitempty"`
	Error      string `json:"error,omitempty"`
}

func CreateInvoiceHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateInvoiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Email == "" {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}

	client := NewLavaClient(lavaAPIKey, lavaProductID)
	resp, err := client.CreateInvoice(req.Email)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CreateInvoiceResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	if resp.ID != "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CreateInvoiceResponse{
			Success:    true,
			InvoiceID:  resp.ID,
			PaymentURL: resp.PaymentURL,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(CreateInvoiceResponse{
		Success: false,
		Error:   "Failed to create invoice",
	})
}

func GetSubscriptionStatus(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "user_id required", http.StatusBadRequest)
		return
	}

	var sub database.Subscription
	if err := database.DB.Where("user_id = ?", userID).Order("created_at desc").First(&sub).Error; err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "none",
			"active": false,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     sub.Status,
		"active":     sub.Status == "active",
		"expires_at": sub.ExpiresAt,
	})
}