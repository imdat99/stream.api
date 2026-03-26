package auth

import "stream.api/internal/database/model"

type LoginCommand struct {
	Email    string
	Password string
}

type RegisterCommand struct {
	Email       string
	Username    string
	Password    string
	RefUsername string
}

type ChangePasswordCommand struct {
	User *model.User
}
