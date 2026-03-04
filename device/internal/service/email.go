package service

import (
	"fmt"
	"net/smtp"
)

// EmailService sends transactional emails via plain SMTP (works with Mailhog).
type EmailService struct {
	addr string
	from string
}

func NewEmailService(host, port, from string) *EmailService {
	return &EmailService{addr: host + ":" + port, from: from}
}

// SendDeviceApprovalCode sends the one-time approval code to the user's email.
func (e *EmailService) SendDeviceApprovalCode(to, deviceName, code string) error {
	subject := "Validation de votre nouveau device"
	body := fmt.Sprintf(
		"Bonjour,\r\n\r\n"+
			"Un nouveau device \"%s\" demande à être enregistré sur votre compte.\r\n\r\n"+
			"Votre code de validation : %s\r\n\r\n"+
			"Ce code expire dans 30 minutes.\r\n\r\n"+
			"Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.\r\n",
		deviceName, code,
	)

	msg := []byte(
		"To: " + to + "\r\n" +
			"From: " + e.from + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"\r\n" +
			body,
	)

	// nil auth — Mailhog accepts unauthenticated connections
	return smtp.SendMail(e.addr, nil, e.from, []string{to}, msg)
}
