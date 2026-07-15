package payment

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/l7-shred/core/internal/database"
)

var (
	webhookSecret = "ObeliskWebhookKey2026"
)

func HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	key := r.Header.Get("X-Api-Key")
	if key != webhookSecret {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	switch payload.EventType {
	case "payment.success":
		handlePaymentSuccess(payload)
	case "payment.failed":
		handlePaymentFailed(payload)
	case "subscription.recurring.payment.success":
		handleSubscriptionRenewal(payload)
	case "subscription.recurring.payment.failed":
		handleSubscriptionFailed(payload)
	case "subscription.cancelled":
		handleSubscriptionCancelled(payload)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func handlePaymentSuccess(payload WebhookPayload) {
	userID := payload.Data.BuyerID
	if userID == "" {
		return
	}

	sub := database.Subscription{
		UserID:             userID,
		LavaSubscriptionID: payload.Data.SubscriptionID,
		ProductID:          payload.Data.ProductID,
		Status:             "active",
		ExpiresAt:          time.Now().Add(30 * 24 * time.Hour),
	}

	database.DB.Create(&sub)
}

func handlePaymentFailed(payload WebhookPayload) {
	// log
}

func handleSubscriptionRenewal(payload WebhookPayload) {
	var sub database.Subscription
	if err := database.DB.Where("lava_subscription_id = ?", payload.Data.SubscriptionID).First(&sub).Error; err != nil {
		return
	}

	sub.ExpiresAt = time.Now().Add(30 * 24 * time.Hour)
	sub.Status = "active"
	database.DB.Save(&sub)
}

func handleSubscriptionFailed(payload WebhookPayload) {
	var sub database.Subscription
	if err := database.DB.Where("lava_subscription_id = ?", payload.Data.SubscriptionID).First(&sub).Error; err != nil {
		return
	}

	sub.Status = "expired"
	database.DB.Save(&sub)
}

func handleSubscriptionCancelled(payload WebhookPayload) {
	var sub database.Subscription
	if err := database.DB.Where("lava_subscription_id = ?", payload.Data.SubscriptionID).First(&sub).Error; err != nil {
		return
	}

	sub.Status = "cancelled"
	database.DB.Save(&sub)
}