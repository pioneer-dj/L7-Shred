package database

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID             uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Email          string     `gorm:"type:varchar(255);unique;not null"`
	PasswordHash   string     `gorm:"type:varchar(255);not null"`
	Name           string     `gorm:"type:varchar(255);default:''"`
	CreatedAt      time.Time  `gorm:"autoCreateTime"`
	UpdatedAt      time.Time  `gorm:"autoUpdateTime"`
	EmailVerified  bool       `gorm:"default:false"`
	TrialStartedAt *time.Time `gorm:"type:timestamptz"`
	TrialEndsAt    *time.Time `gorm:"type:timestamptz"`
	Status         string     `gorm:"type:varchar(50);default:'pending_verification'"`
	VerificationCode        string     `gorm:"type:varchar(10)"`
	VerificationCodeExpires *time.Time `gorm:"type:timestamptz"`

	Sessions          []Session          `gorm:"foreignKey:UserID"`
	EmailVerification []EmailVerification `gorm:"foreignKey:UserID"`
	PasswordResets    []PasswordReset    `gorm:"foreignKey:UserID"`
}

func (User) TableName() string {
	return "users"
}

type Session struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID       uuid.UUID `gorm:"type:uuid;not null"`
	RefreshToken string    `gorm:"type:varchar(500);not null"`
	ExpiresAt    time.Time `gorm:"type:timestamptz;not null"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	IPAddress    string    `gorm:"type:varchar(45)"`
	UserAgent    string    `gorm:"type:text"`

	User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

func (Session) TableName() string {
	return "sessions"
}

type EmailVerification struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID    uuid.UUID `gorm:"type:uuid;not null"`
	Token     string    `gorm:"type:varchar(255);unique;not null"`
	ExpiresAt time.Time `gorm:"type:timestamptz;not null"`
	CreatedAt time.Time `gorm:"autoCreateTime"`

	User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

func (EmailVerification) TableName() string {
	return "email_verifications"
}

type PasswordReset struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null"`
	Token     string     `gorm:"type:varchar(255);unique;not null"`
	ExpiresAt time.Time  `gorm:"type:timestamptz;not null"`
	CreatedAt time.Time  `gorm:"autoCreateTime"`
	UsedAt    *time.Time `gorm:"type:timestamptz"`

	User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

func (PasswordReset) TableName() string {
	return "password_resets"
}

type Subscription struct {
	ID                   string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID               string    `gorm:"type:uuid;not null;index"`
	LavaSubscriptionID   string    `gorm:"type:varchar(255);not null;index"`
	ProductID            string    `gorm:"type:varchar(255);not null"`
	Status               string    `gorm:"type:varchar(50);not null;default:'pending'"`
	ExpiresAt            time.Time `gorm:"not null"`
	CreatedAt            time.Time `gorm:"autoCreateTime"`
	UpdatedAt            time.Time `gorm:"autoUpdateTime"`

	User User `gorm:"foreignKey:UserID"`
}

func (Subscription) TableName() string {
	return "subscriptions"
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&User{}, &Session{}, &EmailVerification{}, &PasswordReset{}, &Subscription{})
}