package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/l7-shred/core/internal/auth"
	"github.com/l7-shred/core/internal/database"
	"gorm.io/gorm"
)

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type UpdateNameRequest struct {
	Name string `json:"name"`
}

type UpdatePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	Status       string `json:"status"`
}

type UserResponse struct {
	ID             string     `json:"id"`
	Email          string     `json:"email"`
	Name           string     `json:"name"`
	EmailVerified  bool       `json:"email_verified"`
	Status         string     `json:"status"`
	TrialStartedAt *time.Time `json:"trial_started"`
	TrialEndsAt    *time.Time `json:"trial_ends"`
	CreatedAt      time.Time  `json:"created_at"`
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		sendJSONError(w, "email and password are required", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		sendJSONError(w, "password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	var existingUser database.User
	if err := database.DB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		sendJSONError(w, "user already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		sendJSONError(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	trialEndsAt := now.Add(7 * 24 * time.Hour)

	name := req.Name
	if name == "" {
		name = req.Email
	}

	user := database.User{
		Email:          req.Email,
		PasswordHash:   hashedPassword,
		Name:           name,
		EmailVerified:  true,
		TrialStartedAt: &now,
		TrialEndsAt:    &trialEndsAt,
		Status:         "active",
	}

	if err := database.DB.Create(&user).Error; err != nil {
		sendJSONError(w, "failed to create user", http.StatusInternalServerError)
		return
	}

	accessToken, err := auth.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		sendJSONError(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := auth.GenerateRefreshToken(user.ID)
	if err != nil {
		sendJSONError(w, "failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	session := database.Session{
		UserID:       user.ID,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	}

	if err := database.DB.Create(&session).Error; err != nil {
		sendJSONError(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID.String(),
		Email:        user.Email,
		Status:       user.Status,
	})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		sendJSONError(w, "email and password are required", http.StatusBadRequest)
		return
	}

	var user database.User
	if err := database.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			sendJSONError(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		sendJSONError(w, "database error", http.StatusInternalServerError)
		return
	}

	if !auth.CheckPasswordHash(req.Password, user.PasswordHash) {
		sendJSONError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	accessToken, err := auth.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		sendJSONError(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := auth.GenerateRefreshToken(user.ID)
	if err != nil {
		sendJSONError(w, "failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	session := database.Session{
		UserID:       user.ID,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	}

	if err := database.DB.Create(&session).Error; err != nil {
		sendJSONError(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID.String(),
		Email:        user.Email,
		Status:       user.Status,
	})
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		sendJSONError(w, "refresh token is required", http.StatusBadRequest)
		return
	}

	var session database.Session
	if err := database.DB.Where("refresh_token = ?", req.RefreshToken).First(&session).Error; err != nil {
		sendJSONError(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	if session.ExpiresAt.Before(time.Now()) {
		database.DB.Delete(&session)
		sendJSONError(w, "refresh token expired", http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		sendJSONError(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	parsedID, err := uuid.Parse(userID)
	if err != nil {
		sendJSONError(w, "invalid user id", http.StatusInternalServerError)
		return
	}

	var user database.User
	if err := database.DB.Where("id = ?", parsedID).First(&user).Error; err != nil {
		sendJSONError(w, "user not found", http.StatusUnauthorized)
		return
	}

	database.DB.Delete(&session)

	newAccessToken, err := auth.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		sendJSONError(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := auth.GenerateRefreshToken(user.ID)
	if err != nil {
		sendJSONError(w, "failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	newSession := database.Session{
		UserID:       user.ID,
		RefreshToken: newRefreshToken,
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	}

	if err := database.DB.Create(&newSession).Error; err != nil {
		sendJSONError(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		UserID:       user.ID.String(),
		Email:        user.Email,
		Status:       user.Status,
	})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		sendJSONError(w, "refresh token is required", http.StatusBadRequest)
		return
	}

	if err := database.DB.Where("refresh_token = ?", req.RefreshToken).Delete(&database.Session{}).Error; err != nil {
		sendJSONError(w, "failed to delete session", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "logged out successfully"})
}

func MeHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(UserContextKey).(*auth.Claims)
	if !ok {
		sendJSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		sendJSONError(w, "invalid user id", http.StatusInternalServerError)
		return
	}

	var user database.User
	if err := database.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		sendJSONError(w, "user not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{
		ID:             user.ID.String(),
		Email:          user.Email,
		Name:           user.Name,
		EmailVerified:  user.EmailVerified,
		Status:         user.Status,
		TrialStartedAt: user.TrialStartedAt,
		TrialEndsAt:    user.TrialEndsAt,
		CreatedAt:      user.CreatedAt,
	})
}

func UpdateNameHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(UserContextKey).(*auth.Claims)
	if !ok {
		sendJSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req UpdateNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		sendJSONError(w, "name is required", http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		sendJSONError(w, "invalid user id", http.StatusInternalServerError)
		return
	}

	var user database.User
	if err := database.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		sendJSONError(w, "user not found", http.StatusNotFound)
		return
	}

	user.Name = req.Name
	if err := database.DB.Save(&user).Error; err != nil {
		sendJSONError(w, "failed to update name", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{
		ID:             user.ID.String(),
		Email:          user.Email,
		Name:           user.Name,
		EmailVerified:  user.EmailVerified,
		Status:         user.Status,
		TrialStartedAt: user.TrialStartedAt,
		TrialEndsAt:    user.TrialEndsAt,
		CreatedAt:      user.CreatedAt,
	})
}

func UpdatePasswordHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(UserContextKey).(*auth.Claims)
	if !ok {
		sendJSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req UpdatePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		sendJSONError(w, "current and new password are required", http.StatusBadRequest)
		return
	}

	if len(req.NewPassword) < 6 {
		sendJSONError(w, "new password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		sendJSONError(w, "invalid user id", http.StatusInternalServerError)
		return
	}

	var user database.User
	if err := database.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		sendJSONError(w, "user not found", http.StatusNotFound)
		return
	}

	if !auth.CheckPasswordHash(req.CurrentPassword, user.PasswordHash) {
		sendJSONError(w, "current password is incorrect", http.StatusUnauthorized)
		return
	}

	newHashedPassword, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		sendJSONError(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	user.PasswordHash = newHashedPassword
	if err := database.DB.Save(&user).Error; err != nil {
		sendJSONError(w, "failed to update password", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{
		ID:             user.ID.String(),
		Email:          user.Email,
		Name:           user.Name,
		EmailVerified:  user.EmailVerified,
		Status:         user.Status,
		TrialStartedAt: user.TrialStartedAt,
		TrialEndsAt:    user.TrialEndsAt,
		CreatedAt:      user.CreatedAt,
	})
}

func DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(UserContextKey).(*auth.Claims)
	if !ok {
		sendJSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		sendJSONError(w, "invalid user id", http.StatusInternalServerError)
		return
	}

	if err := database.DB.Where("user_id = ?", userID).Delete(&database.Session{}).Error; err != nil {
		sendJSONError(w, "failed to delete sessions", http.StatusInternalServerError)
		return
	}

	if err := database.DB.Where("id = ?", userID).Delete(&database.User{}).Error; err != nil {
		sendJSONError(w, "failed to delete user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "account deleted successfully"})
}