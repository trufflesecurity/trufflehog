package models

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username" example:"admin"`
	Password string `json:"password" example:"admin123"`
}

// LoginResponse represents successful login response
type LoginResponse struct {
	Token    string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	Username string `json:"username" example:"admin"`
	UserID   string `json:"user_id" example:"uuid"`
}

// RegisterRequest represents registration data
type RegisterRequest struct {
	Username string `json:"username" example:"newuser"`
	Password string `json:"password" example:"securepassword"`
	Email    string `json:"email" example:"user@example.com"`
}

// User represents a user account
type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	IsActive  bool   `json:"is_active"`
	CreatedAt string `json:"created_at"`
}

