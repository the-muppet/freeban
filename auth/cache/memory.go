package cache

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/mtgban/mtgban-website/auth/models"
	"github.com/mtgban/mtgban-website/auth/repo"
)

type userID string

type cacheEntry struct {
	data         *models.UserData
	lastModified time.Time
	expiry       time.Time
}

type UserCache struct {
	users           sync.Map
	lastSync        time.Time
	mu              sync.RWMutex
	logger          *log.Logger
	metrics         *CacheMetrics
	cleanupInterval time.Duration
	defaultTTL      time.Duration
}

type CacheMetrics struct {
	hits uint64

	misses uint64
	mu     sync.RWMutex
}

func NewCache(opts *CacheOptions) Cache {
	if opts == nil {

		opts = DefaultCacheOptions()
	}

	if opts.Logger == nil {
		opts.Logger = log.New(os.Stdout, opts.LogPrefix, opts.LogFlags)
	}

	cache := &UserCache{
		users:           sync.Map{},
		lastSync:        time.Now(),
		logger:          opts.Logger,
		cleanupInterval: opts.CleanupInterval,
		defaultTTL:      opts.DefaultTTL,
	}

	if opts.EnableMetrics {
		cache.metrics = &CacheMetrics{}
	}

	if opts.CleanupInterval > 0 {
		go cache.periodicCleanup(context.Background())
	}

	return cache
}

func (c *UserCache) GetUserFromContext(ctx context.Context) (*models.UserData, error) {
	userID, ok := ctx.Value(models.UserContextKey).(string)

	if !ok {
		return nil, fmt.Errorf("user_id not found in context")
	}
	return c.GetUser(userID)
}

func (c *UserCache) GetAllUsers() map[string]*models.UserData {

	users := make(map[string]*models.UserData)

	c.users.Range(func(key, value interface{}) bool {
		entry := value.(*cacheEntry)
		if !entry.isExpired() {
			users[string(key.(userID))] = entry.data
		}
		return true
	})
	return users
}

func (c *UserCache) GetUser(id string) (*models.UserData, error) {
	user, err := c.getUserWithError(id)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (c *UserCache) getUserWithError(id string) (*models.UserData, error) {
	if entry, ok := c.users.Load(userID(id)); ok {
		cacheEntry := entry.(*cacheEntry)
		if cacheEntry.isExpired() {
			c.DeleteUser(id)
			if c.metrics != nil {
				c.metrics.recordMiss()
			}
			return nil, fmt.Errorf("cache entry expired")
		}
		if c.metrics != nil {
			c.metrics.recordHit()
		}
		return cacheEntry.data, nil
	}
	if c.metrics != nil {
		c.metrics.recordMiss()
	}
	return nil, nil
}

func (c *UserCache) SetUser(userData *models.UserData) error {
	if userData == nil {

		return fmt.Errorf("attempted to cache nil UserData")
	}
	entry := &cacheEntry{
		data:         userData,
		lastModified: time.Now(),
		expiry:       time.Now().Add(c.defaultTTL),
	}
	c.users.Store(userID(userData.ID), entry)
	return nil
}

func (c *UserCache) DeleteUser(id string) error {
	c.users.Delete(userID(id))

	c.logger.Printf("Deleted user %s from cache", id)
	return nil
}

func (c *UserCache) GetLastModified(id string) time.Time {
	if entry, ok := c.users.Load(userID(id)); ok {

		return entry.(*cacheEntry).lastModified
	}
	return time.Time{}
}

func (c *UserCache) LoadInitialData(ctx context.Context, repo repo.UserRepository) error {
	userIDs, err := repo.GetAllUserIDs(ctx)
	if err != nil {

		return fmt.Errorf("failed to fetch user IDs: %w", err)
	}

	var loadedCount int
	for _, id := range userIDs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			user, err := repo.GetUserByID(ctx, id)
			if err != nil {
				c.logger.Printf("WARNING: Failed to fetch user %s: %v", id, err)
				continue
			}
			if err := c.SetUser(user); err != nil {
				c.logger.Printf("WARNING: Failed to cache user %s: %v", id, err)
				continue
			}
			loadedCount++
		}
	}

	c.mu.Lock()
	c.lastSync = time.Now()
	c.mu.Unlock()

	c.logger.Printf("Successfully loaded %d/%d users into cache", loadedCount, len(userIDs))
	return nil
}

func (c *UserCache) GetLastSync() time.Time {
	c.mu.RLock()

	defer c.mu.RUnlock()
	return c.lastSync
}

func (c *UserCache) UpdateLastSync() {
	c.mu.Lock()

	defer c.mu.Unlock()
	c.lastSync = time.Now()
}

func (c *UserCache) GetMetrics() (hits, misses uint64) {
	if c.metrics == nil {

		return 0, 0
	}
	c.metrics.mu.RLock()
	defer c.metrics.mu.RUnlock()
	return c.metrics.hits, c.metrics.misses
}

func (c *UserCache) periodicCleanup(ctx context.Context) {
	ticker := time.NewTicker(c.cleanupInterval)

	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

func (c *UserCache) cleanup() {
	c.users.Range(func(key, value interface{}) bool {

		entry := value.(*cacheEntry)
		if entry.isExpired() {
			c.users.Delete(key)
		}
		return true
	})
}

func (e *cacheEntry) isExpired() bool {
	return !e.expiry.IsZero() && time.Now().After(e.expiry)
}

func (c *UserCache) Shutdown(ctx context.Context) error {
	if c == nil {

		return nil
	}

	c.logger.Printf("Starting UserCache shutdown")
	done := make(chan struct{})
	go func() {
		c.users.Range(func(key, value interface{}) bool {
			select {
			case <-ctx.Done():
				return false
			default:
				c.users.Delete(key)
				return true
			}
		})
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		c.logger.Printf("UserCache shutdown complete")
		return nil
	}
}

func (m *CacheMetrics) recordHit() {
	m.mu.Lock()

	m.hits++
	m.mu.Unlock()
}

func (m *CacheMetrics) recordMiss() {
	m.mu.Lock()

	m.misses++
	m.mu.Unlock()
}
