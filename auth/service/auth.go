package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/mtgban-website/auth/cache"
	"github.com/mtgban/mtgban-website/auth/models"
	"github.com/mtgban/mtgban-website/auth/repo"

	"github.com/golang-jwt/jwt/v5"
)

type AuthService struct {
	client   repo.SupabaseClient
	repo     repo.UserRepository
	cache    cache.Cache
	logger   *log.Logger
	config   *models.AuthConfig
	shutdown chan struct{}
	wg       sync.WaitGroup
}

func NewAuthService(client repo.SupabaseClient, config *models.AuthConfig, logger *log.Logger) (*AuthService, error) {
	if config == nil {
		config = models.DefaultAuthConfig()
	}

	jwtSecret := os.Getenv("SUPABASE_JWT_SECRET")
	if jwtSecret == "" {
		return nil, fmt.Errorf("SUPABASE_JWT_SECRET environment variable not set")
	}
	config.JWTSecret = []byte(jwtSecret)
	if logger == nil {
		logger = log.New(os.Stdout, "[AUTH] ", log.LstdFlags)
	}

	cache := cache.NewCache(cache.DefaultCacheOptions())
	repo := repo.NewSupabaseUserRepository(client)

	service := &AuthService{
		client:   client,
		repo:     repo,
		cache:    cache,
		logger:   logger,
		config:   config,
		shutdown: make(chan struct{}),
	}

	// Initial cache load
	if err := service.cache.LoadInitialData(context.Background(), service.repo); err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Start background refresh if interval is set
	if config.RefreshInterval > 0 {
		service.wg.Add(1)
		go service.backgroundRefresh()
	}

	return service, nil
}
func (s *AuthService) backgroundRefresh() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.refreshCache(context.Background()); err != nil {
				s.logger.Printf("Background refresh failed: %v", err)
			}
		case <-s.shutdown:
			return
		}
	}
}
func (s *AuthService) refreshCache(ctx context.Context) error {
	// Get current cache state
	currentUsers := s.cache.GetAllUsers()

	// Fetch all current valid user IDs
	allUserIDs, err := s.repo.GetAllUserIDs(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch user IDs: %w", err)
	}

	// Check context after expensive DB call
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context error after fetching IDs: %w", err)
	}

	// Create map of valid users for O(1) lookup
	validUsers := make(map[string]struct{}, len(allUserIDs))
	for _, id := range allUserIDs {
		validUsers[id] = struct{}{}
	}

	// Track changes for atomicity
	updates := make(map[string]*models.UserData)
	deletions := make([]string, 0)

	// Find users to delete (in cache but not in DB)
	for userID := range currentUsers {
		if _, exists := validUsers[userID]; !exists {
			deletions = append(deletions, userID)
		}
	}

	// Find users to update (in DB)
	for _, userID := range allUserIDs {
		userData, err := s.repo.GetUserByID(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to fetch user %s: %w", userID, err)
		}
		updates[userID] = userData
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context error before applying changes: %w", err)
	}

	for userID := range updates {
		s.cache.SetUser(updates[userID])
	}
	for _, userID := range deletions {
		s.cache.DeleteUser(userID)
	}

	if c, ok := s.cache.(*cache.UserCache); ok {
		c.UpdateLastSync()
	}

	s.logger.Printf("Cache refresh completed: updated %d users, removed %d users",
		len(updates), len(deletions))
	return nil
}
func (s *AuthService) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		http.Error(w, "Invalid content type", http.StatusUnsupportedMediaType)
		return
	}

	if s.config.WebhookSecretKey != "" {
		if !cryptoSecureCompare(
			[]byte(r.Header.Get("X-Webhook-Secret")),
			[]byte(s.config.WebhookSecretKey),
		) {

			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var payload models.WebhookPayload
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&payload); err != nil {
		s.logger.Printf("Failed to decode webhook payload: %v", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	if payload.Type == "" || payload.Table == "" {
		s.logger.Printf("Missing required fields in webhook payload")
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	validTypes := map[string]bool{
		"INSERT": true,
		"UPDATE": true,
		"DELETE": true,
	}

	if !validTypes[payload.Type] {
		s.logger.Printf("Invalid webhook type: %s", payload.Type)
		http.Error(w, "Invalid webhook type", http.StatusBadRequest)
		return
	}

	if payload.Table != "users" {
		s.logger.Printf("Skipping webhook for non-user table: %s", payload.Table)
		w.WriteHeader(http.StatusOK)
		return
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Printf("Panic in webhook handler: %v", r)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()

		switch payload.Type {
		case "INSERT", "UPDATE":
			if err := s.handleUserUpsert(payload.Record); err != nil {
				s.logger.Printf("Failed to handle user upsert: %v", err)
				http.Error(w, "Failed to process user data", http.StatusBadRequest)
				return
			}

		case "DELETE":
			if err := s.handleUserDelete(payload.Record); err != nil {
				s.logger.Printf("Failed to handle user delete: %v", err)
				http.Error(w, "Failed to process deletion", http.StatusBadRequest)
				return
			}
		}
	}()

	w.WriteHeader(http.StatusOK)
}

func cryptoSecureCompare(b1 []byte, b2 []byte) bool {
	panic("unimplemented")
}
func (s *AuthService) handleUserUpsert(record map[string]interface{}) error {
	userData, err := s.parseUserData(record)
	if err != nil {
		return fmt.Errorf("failed to parse user data: %w", err)

	}

	s.cache.SetUser(userData)
	s.logger.Printf("Updated cache for user %s via webhook", userData.ID)
	return nil

}
func (s *AuthService) handleUserDelete(record map[string]interface{}) error {
	userID, ok := record["id"].(string)
	if !ok {
		return fmt.Errorf("invalid or missing user ID in delete record")
	}

	s.cache.DeleteUser(userID)
	s.logger.Printf("Removed user %s from cache via webhook", userID)
	return nil

}

func (s *AuthService) Shutdown(ctx context.Context) error {
	s.logger.Printf("Initiating graceful shutdown")
	close(s.shutdown)

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Printf("Graceful shutdown completed")
		return nil
	case <-ctx.Done():
		return fmt.Errorf("shutdown context expired: %w", ctx.Err())
	}
}

func (s *AuthService) parseUserData(record map[string]interface{}) (*models.UserData, error) {
	// Extract and validate role first
	roleStr, ok := record["role"].(string)
	if !ok {

		return nil, fmt.Errorf("missing or invalid role field")
	}
	role := models.UserRole(roleStr)
	if !role.IsValid() {
		return nil, fmt.Errorf("invalid role value: %s", roleStr)
	}

	userData := &models.UserData{
		ID:   record["id"].(string),
		Role: role,
	}

	if ts, ok := record["created_at"].(string); ok {
		createdAt, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return nil, fmt.Errorf("invalid created_at timestamp: %w", err)
		}
		userData.CreatedAt = createdAt
	}

	if ts, ok := record["last_sign_in"].(string); ok {
		lastSignIn, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return nil, fmt.Errorf("invalid last_sign_in timestamp: %w", err)
		}
		userData.LastSignIn = lastSignIn
	}

	return userData, nil
}
func (s *AuthService) HasRequiredRole(role, requiredRole models.UserRole) bool {
	// Admin has all permissions
	if role == models.RoleAdmin {
		return true

	}

	// Direct match
	if role == requiredRole {
		return true
	}

	// Check inherited roles
	allowedRoles, exists := models.RoleHierarchy[role]
	if !exists {
		return false
	}

	for _, r := range allowedRoles {
		if r == requiredRole {
			return true
		}
	}
	return false
}
func (s *AuthService) AuthMiddleware(requiredRole models.UserRole) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			newCtx, err := s.authenticateAndAuthorize(ctx, r, requiredRole)
			if err != nil {
				s.handleAuthError(w, err)
				return
			}

			next.ServeHTTP(w, r.WithContext(newCtx))
		})
	}
}
func (s *AuthService) handleAuthError(w http.ResponseWriter, err error) {
	if authErr, ok := err.(*models.AuthError); ok {
		s.logger.Printf("Authentication error: %v, code: %d", authErr, authErr.Code)
		http.Error(w, authErr.Message, authErr.Code)
		return
	}

	s.logger.Printf("Internal server error: %v", err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

func (s *AuthService) authenticateAndAuthorize(ctx context.Context, r *http.Request, requiredRole models.UserRole) (context.Context, error) {
	if err := ctx.Err(); err != nil {
		return ctx, &models.AuthError{
			Code:    http.StatusServiceUnavailable,
			Message: "Request cancelled or timed out",
			Err:     err,
		}
	}

	token, err := s.extractAndValidateToken(r)
	if err != nil {
		return ctx, err
	}

	user, err := s.getUserFromToken(ctx, token)
	if err != nil {
		return ctx, err
	}

	if !s.HasRequiredRole(user.Role, requiredRole) {
		return ctx, &models.AuthError{

			Code:    http.StatusForbidden,
			Message: "Insufficient permissions",
		}
	}

	return context.WithValue(ctx, models.UserContextKey, user), nil

}

func (s *AuthService) extractAndValidateToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", &models.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Missing authorization header",
		}
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return "", &models.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid authorization format",
		}
	}

	return tokenString, nil
}

func (s *AuthService) getUserFromToken(ctx context.Context, tokenString string) (*models.UserData, error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.config.JWTSecret, nil
	})

	if err != nil {
		return nil, &models.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid token",
			Err:     err,
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, &models.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid token claims",
		}
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return nil, &models.AuthError{
			Code:    http.StatusUnauthorized,
			Message: "No user ID in token",
		}
	}

	return s.GetUser(ctx, userID)
}

func (s *AuthService) GetUserFromContext(ctx context.Context) (*models.UserData, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil context")
	}

	value := ctx.Value(models.UserContextKey)
	if value == nil {
		return nil, fmt.Errorf("no user in context")
	}

	user, ok := value.(*models.UserData)
	if !ok {
		return nil, fmt.Errorf("invalid user type in context")
	}

	return user, nil
}

func (s *AuthService) GetUser(ctx context.Context, userID string) (*models.UserData, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context error: %w", err)
	}

	cacheUser, err := s.cache.GetUser(userID)
	if err != nil {
		s.logger.Printf("Cache error for user %s: %v", userID, err)
	} else if cacheUser != nil {
		return cacheUser, nil
	}

	dbUser, err := s.repo.GetUserByID(ctx, userID)

	if err != nil {
		return nil, &models.AuthError{
			Code:    http.StatusNotFound,
			Message: "User not found",
			Err:     err,
		}
	}

	if err := s.cache.SetUser(dbUser); err != nil {
		s.logger.Printf("Warning: failed to update cache for user %s: %v", userID, err)
	}

	return dbUser, nil
}
