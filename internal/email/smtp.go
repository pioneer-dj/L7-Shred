package email

import (
	"fmt"
	"math/rand"
	"net/smtp"
)

type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

type SMTPClient struct {
	config SMTPConfig
}

func NewSMTPClient(config SMTPConfig) *SMTPClient {
	return &SMTPClient{
		config: config,
	}
}

func (c *SMTPClient) SendVerificationCodeHTML(toEmail, code string) error {
	subject := "Obelisk VPN - Email Verification"
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; background-color: #0A051C; color: #FFFFFF; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background-color: #120C25; border-radius: 16px; padding: 30px; border: 1px solid #2C2144; }
        .header { text-align: center; margin-bottom: 30px; }
        .code { font-size: 32px; font-weight: bold; color: #7A06D9; background-color: #1A0D3A; padding: 16px 32px; border-radius: 12px; text-align: center; letter-spacing: 4px; display: inline-block; margin: 20px 0; }
        .footer { margin-top: 30px; color: #786A98; font-size: 12px; text-align: center; }
        .expiry { color: #FFB84D; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Obelisk VPN</h1>
            <p style="color: #B7A9D9;">Email Verification</p>
        </div>
        <p>Hello!</p>
        <p>Thank you for signing up for Obelisk VPN. Please use the verification code below to complete your registration:</p>
        <div style="text-align: center;">
            <div class="code">%s</div>
        </div>
        <p class="expiry">⏱ This code will expire in 10 minutes.</p>
        <p>If you didn't request this, please ignore this email.</p>
        <div class="footer">
            <p>Best regards,<br>Obelisk VPN Team</p>
        </div>
    </div>
</body>
</html>
`, code)

	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s", c.config.From, toEmail, subject, htmlBody)

	addr := fmt.Sprintf("%s:%s", c.config.Host, c.config.Port)

	auth := smtp.PlainAuth("", c.config.Username, c.config.Password, c.config.Host)

	err := smtp.SendMail(addr, auth, c.config.From, []string{toEmail}, []byte(message))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func GenerateVerificationCode() string {
	const digits = "0123456789"
	code := make([]byte, 6)
	for i := range code {
		code[i] = digits[rand.Intn(len(digits))]
	}
	return string(code)
}

func SendVerificationCodeWithHTML(client *SMTPClient, toEmail, code string) error {
	return client.SendVerificationCodeHTML(toEmail, code)
}