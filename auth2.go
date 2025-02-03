package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"math/rand"

	"github.com/golang-jwt/jwt/v5"
	"github.com/supabase-community/supabase-go"
	"golang.org/x/time/rate"
)

type Config struct {
	RateLimit      rate.Limit
	BurstLimit     int
	JWTSecret      []byte
	ContextTimeout time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		RateLimit:      rate.Every(time.Second),
		BurstLimit:     10,
		ContextTimeout: 5 * time.Second,
	}
}

type UserRole string
type contextKey string

const userContextKey contextKey = "user"

const (
	RoleApi     UserRole = "api"
	RoleTest    UserRole = "test"
	RoleFree    UserRole = "free"
	RolePioneer UserRole = "pioneer"
	RoleModern  UserRole = "modern"
	RoleLegacy  UserRole = "legacy"
	RoleVintage UserRole = "vintage"
	RoleAdmin   UserRole = "admin"
)

var RoleHierarchy = map[UserRole][]UserRole{
    RoleFree:    {},
    RolePioneer: {RoleFree},
    RoleModern:  {RoleFree, RolePioneer},
    RoleLegacy:  {RoleFree, RolePioneer, RoleModern},
    RoleVintage: {RoleFree, RolePioneer, RoleModern, RoleLegacy},
    RoleAdmin:   {RoleFree, RolePioneer, RoleModern, RoleLegacy, RoleVintage},
}


type UserData struct {
	ID         string    `json:"id"`
	Role       UserRole  `json:"role"`
	CreatedAt  time.Time `json:"created_at"`
	LastSignIn time.Time `json:"last_sign_in"`
}

type DatabaseEvent struct {
	Type   string                 `json:"type"`
	Record map[string]interface{} `json:"record"`
}

type SupabaseClient interface {
	From(table string) *supabase.QueryBuilder
	DB() *supabase.QueryBuilder
}

type AuthService struct {
	client    SupabaseClient
	cache     *UserCache
	logger    *log.Logger
	limiter   *rate.Limiter
	config    *Config
    shutdown chan struct{}
    shutdownWg sync.WaitGroup
}

type UserCache struct {
    users    sync.Map
    client   SupabaseClient
    logger   *log.Logger
    eventQueue chan DatabaseEvent
    shutdown chan struct{}
    shutdownWg sync.WaitGroup
}

func NewAuthService(client SupabaseClient, config *Config) (*AuthService, error) {
	if config == nil {
		config = DefaultConfig()
	}

	jwtSecret := os.Getenv("SUPABASE_JWT_SECRET")
	if jwtSecret == "" {
		return nil, fmt.Errorf("SUPABASE_JWT_SECRET environment variable not set")
	}
    config.JWTSecret = []byte(jwtSecret)

	cache := &UserCache{
		users:    sync.Map{},
		client:   client,
		logger:   log.New(os.Stdout, "[CACHE] ", log.LstdFlags),
		eventQueue: make(chan DatabaseEvent, 100),
        shutdown: make(chan struct{}),
	}

	if err := cache.loadAllUsers(context.Background(), config.ContextTimeout); err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	if err := cache.subscribeToUserChanges(); err != nil {
		return nil, fmt.Errorf("failed to setup subscription: %w", err)
	}

    cache.shutdownWg.Add(1)
    go func() {
        defer cache.shutdownWg.Done()
        cache.startEventProcessor()
    }()

    service := &AuthService{
        client: client,
        cache: cache,
        logger: log.New(os.Stdout, "[AUTH] ", log.LstdFlags),
        limiter: rate.NewLimiter(config.RateLimit, config.BurstLimit),
        config: config,
        shutdown: make(chan struct{}),
    }

    service.shutdownWg.Add(1)
    go func() {
        defer service.shutdownWg.Done()
        service.monitorShutdown()
    }()

    return service, nil

}


func (s *AuthService) Shutdown(ctx context.Context) error {
    s.logger.Printf("Initiating graceful shutdown")
    
    close(s.shutdown)
        
    done := make(chan struct{}, 1)
    go func() {
        s.shutdownWg.Wait()
        s.limiter.SetLimit(0)
        done <- struct{}{}
    }()
    
    select {
    case <-done:
        s.logger.Printf("Graceful shutdown completed successfully")
        return nil
    case <-ctx.Done():
        s.logger.Printf("Shutdown context expired: %v", ctx.Err())
        return fmt.Errorf("shutdown context expired: %w", ctx.Err())
    }
}

func (s *AuthService) monitorShutdown() {
    <-s.shutdown
    s.logger.Printf("Starting graceful shutdown sequence")
    
    close(s.cache.shutdown)
    s.cache.shutdownWg.Wait()

    s.logger.Printf("Cache shutdown completed")
}

func (c *UserCache) getUser(userID string) *UserData {
	if user, ok := c.users.Load(userID); ok {
		return user.(*UserData)
	}
	return nil
}

func (c *UserCache) setUser(userData *UserData) {
	c.users.Store(userData.ID, userData)
}

func (c *UserCache) deleteUser(userID string) {
	c.users.Delete(userID)
}


func (c *UserCache) loadAllUsers(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var users []UserData
	err := c.client.DB().
		From("users").
		Select("id, role, created_at, last_sign_in").
		Execute(&users)

	if err != nil {
		return fmt.Errorf("failed to fetch users: %w, query: select id, role, created_at, last_sign_in from users", err)
	}

	for i := range users {
		c.setUser(&users[i])
	}

    c.logger.Printf("Loaded %d users into cache", len(users))
	return nil
}


func (c *UserCache) subscribeToUserChanges() error {
	subscription := c.client.DB().
		From("users").
		On("postgres_changes", "*", c.handleDatabaseEvent)

	go c.handleSubscriptionErrors(subscription.Errors())
	return nil
}


func (c *UserCache) handleDatabaseEvent(event DatabaseEvent) {
	c.eventQueue <- event
}

func (c *UserCache) startEventProcessor(){
    defer close(c.eventQueue)
    
    for {
        select {
        case event, ok := <-c.eventQueue:
            if !ok {
                c.logger.Printf("Event queue closed, exiting processor")
                return
            }
            c.processDatabaseEvent(event)
        case <-c.shutdown:
            c.logger.Printf("Shutdown signal received, stopping event processor")
            return
        }
    }
}

func (c *UserCache) processDatabaseEvent(event DatabaseEvent) {
    userID, ok := event.Record["id"].(string)
    if !ok {
        c.logger.Printf("Invalid user ID in event: %+v", event)
        return
    }

    switch event.Type {
    case "INSERT", "UPDATE":
        userData, err := parseUserData(event.Record)
        if err != nil {
            c.logger.Printf("Failed to parse user data: %v, event: %+v", err, event)
            return
        }
        c.setUser(userData)

    case "DELETE":
        c.deleteUser(userID)
    }
}

func (c *UserCache) handleSubscriptionErrors(errors <-chan error) {
    maxRetries := getEnvIntWithDefault("MAX_RETRIES", 5)
    initialBackoff := getEnvDurationWithDefault("INITIAL_BACKOFF", time.Second)
    maxBackoff := getEnvDurationWithDefault("MAX_BACKOFF", 30*time.Second)

    retryCount := 0
    backoff := initialBackoff

    for {
        select {
        case err, ok := <-errors:
            if !ok {
                c.logger.Printf("Error channel closed")
                return
            }
            
            c.logger.Printf("Subscription error: %v", err)
            if retryCount >= maxRetries {
                c.logger.Printf("Max retries (%d) exceeded, resetting connection", maxRetries)
                retryCount = 0
                backoff = initialBackoff
            }

            timer := time.NewTimer(backoff)
            select {
            case <-timer.C:
                if err := c.subscribeToUserChanges(); err != nil {
                    c.logger.Printf("Failed to re-subscribe: %v", err)
                    retryCount++
                    
                    backoff = time.Duration(float64(backoff) * 1.5)
                    if backoff > maxBackoff {
                        backoff = maxBackoff
                    }
                    jitter := time.Duration(rand.Float64() * float64(backoff))
                    backoff = backoff + jitter
                    continue
                }
                
                c.logger.Printf("Reconnected subscription successfully")
                retryCount = 0
                backoff = initialBackoff
                
            case <-c.shutdown:
                timer.Stop()
                c.logger.Printf("Shutdown signal received during backoff")
                return
            }

        case <-c.shutdown:
            c.logger.Printf("Shutdown signal received, stopping error handler")
            return
        }
    }
}


func parseUserData(record map[string]interface{}) (*UserData, error) {
	userData := &UserData{
		ID:   record["id"].(string),
		Role: UserRole(record["role"].(string)),
	}

	if ts, ok := record["created_at"].(string); ok {
		createdAt, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return nil, fmt.Errorf("invalid created_at timestamp: %w, record: %+v", err, record)
		}
		userData.CreatedAt = createdAt
	}

	if ts, ok := record["last_sign_in"].(string); ok {
		lastSignIn, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return nil, fmt.Errorf("invalid last_sign_in timestamp: %w, record: %+v", err, record)
		}
		userData.LastSignIn = lastSignIn
	}

	return userData, nil
}


func (s *AuthService) HasRequiredRole(role, requiredRole UserRole) bool {
    if role == RoleAdmin {
        return true
    }

    allowedRoles, exists := RoleHierarchy[role]
    if !exists {
        return false
    }

    for _, allowedRole := range allowedRoles {
        if allowedRole == requiredRole {
            return true
        }
    }
    return role == requiredRole
}


func (s *AuthService) AuthMiddleware(requiredRole UserRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := s.authenticateAndAuthorize(r.Context(), w, r, requiredRole); err != nil {
				s.handleAuthError(w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}


type AuthError struct {
	Code    int
	Message string
	Err     error
}

func (e *AuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (s *AuthService) handleAuthError(w http.ResponseWriter, err error) {
	if authErr, ok := err.(*AuthError); ok {
		s.logger.Printf("Authentication error: %v, code: %d", authErr, authErr.Code)
		http.Error(w, authErr.Message, authErr.Code)
		return
	}

    s.logger.Printf("Internal server error: %v", err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}


func (s *AuthService) authenticateAndAuthorize(ctx context.Context, w http.ResponseWriter, r *http.Request, requiredRole UserRole) error {
	if !s.limiter.Allow() {
		return &AuthError{
			Code:    http.StatusTooManyRequests,
			Message: "Rate limit exceeded",
		}
	}

	token, err := s.extractAndValidateToken(r)
	if err != nil {
		return err
	}

	user, err := s.getUserFromToken(ctx, token)
	if err != nil {
		return err
	}

	if !s.HasRequiredRole(user.Role, requiredRole) {
		return &AuthError{
			Code:    http.StatusForbidden,
			Message: "Insufficient permissions",
		}
	}

	ctx = context.WithValue(ctx, userContextKey, user)
	return nil
}


func (s *AuthService) extractAndValidateToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", &AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Missing authorization header",
		}
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return "", &AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid authorization format",
		}
	}

	return tokenString, nil
}


func (s *AuthService) getUserFromToken(ctx context.Context, tokenString string) (*UserData, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.config.JWTSecret, nil
	})

	if err != nil {
		return nil, &AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid token",
			Err:     err,
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, &AuthError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid token claims",
		}
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return nil, &AuthError{
			Code:    http.StatusUnauthorized,
			Message: "No user ID in token",
		}
	}

	return s.GetUser(ctx, userID)
}


func (s *AuthService) GetUser(ctx context.Context, userID string) (*UserData, error) {
    if user := s.cache.getUser(userID); user != nil {
        return user, nil
    }

	var user UserData
	err := s.client.DB().
		From("users").
		Select("id, role, last_sign_in").
		Single().
		Eq("id", userID).
		Execute(&user)
	if err != nil {
        return nil, fmt.Errorf("failed to fetch user from database: %w, query: select id, role, last_sign_in from users where id = %s", err, userID)
    }
	s.cache.setUser(&user)
	return &user, nil
}

func GetUserFromContext(ctx context.Context) (*UserData, error) {
	user, ok := ctx.Value(userContextKey).(*UserData)
	if !ok {
		return nil, fmt.Errorf("no user in context")
	}
	return user, nil
}


func getEnvIntWithDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}


func getEnvDurationWithDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}