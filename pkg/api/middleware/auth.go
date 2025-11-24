package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/auth"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/models"
)

// JWTAuth middleware to validate JWT tokens
func JWTAuth(c *fiber.Ctx) error {
	// Get token from Authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{
			Error:   "unauthorized",
			Message: "Authorization header required",
			Code:    fiber.StatusUnauthorized,
		})
	}

	// Extract token from "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{
			Error:   "invalid_token",
			Message: "Invalid authorization header format",
			Code:    fiber.StatusUnauthorized,
		})
	}

	token := parts[1]

	// Validate token
	claims, err := auth.ValidateToken(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{
			Error:   "invalid_token",
			Message: "Invalid or expired token",
			Code:    fiber.StatusUnauthorized,
		})
	}

	// Store user info in context
	c.Locals("user_id", claims.UserID)
	c.Locals("username", claims.Username)

	return c.Next()
}

// Optional JWT auth - doesn't fail if no token provided
func OptionalJWTAuth(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Next()
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		claims, err := auth.ValidateToken(parts[1])
		if err == nil {
			c.Locals("user_id", claims.UserID)
			c.Locals("username", claims.Username)
		}
	}

	return c.Next()
}

