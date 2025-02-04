package cache

import (
	"context"
	"log"
	"time"

	"github.com/mtgban/mtgban-website/auth/models"
	"github.com/mtgban/mtgban-website/auth/repo"
)

type Cache interface {
	GetAllUsers() map[string]*models.UserData
	GetUser(userID string) (*models.UserData, error)
	SetUser(user *models.UserData) error
	DeleteUser(userID string) error
	GetLastModified(userID string) time.Time
	GetLastSync() time.Time
	GetUserFromContext(ctx context.Context) (*models.UserData, error)
	UpdateLastSync()

	GetMetrics() (hits uint64, misses uint64)
	LoadInitialData(ctx context.Context, repo repo.UserRepository) error
	Shutdown(ctx context.Context) error
}

type CacheOptions struct {
	Logger          *log.Logger
	LogPrefix       string
	LogFlags        int
	InitialCapacity int
	CleanupInterval time.Duration
	DefaultTTL      time.Duration
	EnableMetrics   bool
}

func DefaultCacheOptions() *CacheOptions {
	return &CacheOptions{
		LogPrefix:       "[CACHE] ",
		LogFlags:        log.LstdFlags | log.Lshortfile,
		InitialCapacity: 100,
		CleanupInterval: 10 * time.Minute,
		DefaultTTL:      24 * time.Hour,
		EnableMetrics:   true,
	}
}
