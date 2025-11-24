package handlers

import (
	"database/sql"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/auth"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/db"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/models"
)

type AuthHandler struct {
	database *db.Database
}

func NewAuthHandler(database *db.Database) *AuthHandler {
	return &AuthHandler{database: database}
}

// Login godoc
// @Summary      User login
// @Description  Authenticate user and get JWT token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body models.LoginRequest true "Login credentials"
// @Success      200 {object} models.LoginResponse
// @Failure      401 {object} models.ErrorResponse
// @Router       /api/v1/auth/login [post]
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req models.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid JSON body",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Validate input
	if req.Username == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "validation_error",
			Message: "Username and password are required",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Get user from database
	var userID uuid.UUID
	var passwordHash string
	var isActive bool
	
	query := `SELECT id, password_hash, is_active FROM users WHERE username = $1`
	err := h.database.DB.QueryRow(query, req.Username).Scan(&userID, &passwordHash, &isActive)
	
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{
			Error:   "invalid_credentials",
			Message: "Invalid username or password",
			Code:    fiber.StatusUnauthorized,
		})
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to authenticate",
			Code:    fiber.StatusInternalServerError,
		})
	}

	// Check if user is active
	if !isActive {
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{
			Error:   "account_disabled",
			Message: "Account is disabled",
			Code:    fiber.StatusUnauthorized,
		})
	}

	// Verify password
	if !auth.CheckPasswordHash(req.Password, passwordHash) {
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{
			Error:   "invalid_credentials",
			Message: "Invalid username or password",
			Code:    fiber.StatusUnauthorized,
		})
	}

	// Generate JWT token
	token, err := auth.GenerateToken(userID, req.Username)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to generate token",
			Code:    fiber.StatusInternalServerError,
		})
	}

	// Update last login
	_, _ = h.database.DB.Exec("UPDATE users SET last_login = $1 WHERE id = $2", time.Now(), userID)

	return c.JSON(models.LoginResponse{
		Token:    token,
		Username: req.Username,
		UserID:   userID.String(),
	})
}

// Register godoc
// @Summary      Register new user
// @Description  Create a new user account
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body models.RegisterRequest true "Registration data"
// @Success      201 {object} models.SuccessResponse
// @Failure      400 {object} models.ErrorResponse
// @Router       /api/v1/auth/register [post]
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var req models.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid JSON body",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Validate input
	if req.Username == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "validation_error",
			Message: "Username and password are required",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Hash password
	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to hash password",
			Code:    fiber.StatusInternalServerError,
		})
	}

	// Insert user
	userID := uuid.New()
	query := `INSERT INTO users (id, username, password_hash, email) VALUES ($1, $2, $3, $4)`
	_, err = h.database.DB.Exec(query, userID, req.Username, passwordHash, req.Email)
	
	if err != nil {
		// Check if username already exists
		if err.Error() == "pq: duplicate key value violates unique constraint \"users_username_key\"" {
			return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
				Error:   "username_exists",
				Message: "Username already exists",
				Code:    fiber.StatusBadRequest,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to create user",
			Code:    fiber.StatusInternalServerError,
		})
	}

	return c.Status(fiber.StatusCreated).JSON(models.SuccessResponse{
		Success: true,
		Message: "User registered successfully",
	})
}

