package store

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// SyscallEvent represents a syscall event to be stored.
type SyscallEvent struct {
	Timestamp   time.Time
	Namespace   string
	PodName     string
	Container   string
	WorkloadKey string
	PID         uint32
	SyscallNr   uint32
	SyscallName string
	Argument    string
	Comm        string
	CgroupID    uint64
	NodeName    string
	Action      string // "observed", "learned", "allowed", "blocked"
}

// SyscallCount represents aggregated syscall counts.
type SyscallCount struct {
	Timestamp   time.Time // Bucketed to minute
	WorkloadKey string
	SyscallName string
	Comm        string
	Argument    string
	Action      string
	Count       uint64
}

// AllowlistEntry represents a syscall in a workload's allowlist.
type AllowlistEntry struct {
	WorkloadKey           string    `json:"workload_key"`
	TemplateHash          string    `json:"template_hash"`
	SyscallName           string    `json:"syscall_name"`
	Argument              string    `json:"argument"`
	IsPrefix              bool      `json:"is_prefix"`
	TrainingStarted       time.Time `json:"training_started"`
	TrainingPeriodSeconds uint32    `json:"training_period_seconds"`
	FirstSeen             time.Time `json:"first_seen"`
	LastSeen              time.Time `json:"last_seen"`
	Risk                  string    `json:"risk"`
}

// PolicyAuditEntry represents a manual change to the security policy.
type PolicyAuditEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	UserID      string    `json:"user_id"`
	WorkloadKey string    `json:"workload_key"`
	Action      string    `json:"action"` // "ALLOW", "BLOCK", "DELETE"
	SyscallName string    `json:"syscall_name"`
	Argument    string    `json:"argument"`
	Reason      string    `json:"reason"`
}

// Config holds store configuration.
type Config struct {
	Host     string
	Port     int
	Database string
	Username string
	Password string
}

// Store manages ClickHouse storage.
type Store struct {
	conn     driver.Conn
	nodeName string

	// Buffered event channel
	eventCh chan *SyscallEvent

	// Seen syscalls for deduplication
	seen   map[string]bool
	seenMu sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new ClickHouse store.
func New(cfg Config) (*Store, error) {
	if cfg.Host == "" {
		cfg.Host = getEnv("CLICKHOUSE_HOST", "localhost")
	}
	if cfg.Port == 0 {
		cfg.Port = 9000
	}
	if cfg.Database == "" {
		cfg.Database = getEnv("CLICKHOUSE_DB", "kubesec")
	}
	if cfg.Username == "" {
		cfg.Username = getEnv("CLICKHOUSE_USER", "kubesec")
	}
	if cfg.Password == "" {
		cfg.Password = getEnv("CLICKHOUSE_PASSWORD", "kubesec123")
	}

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)},
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		DialTimeout:     10 * time.Second,
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Ping to verify connection
	if err := conn.Ping(ctx); err != nil {
		// If the database doesn't exist, try to create it
		log.Printf("[Store] Failed to connect to database %s, attempting to create it...", cfg.Database)

		// Connect to 'default' database instead
		bootstrapConn, berr := clickhouse.Open(&clickhouse.Options{
			Addr: []string{fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)},
			Auth: clickhouse.Auth{
				Database: "default",
				Username: cfg.Username,
				Password: cfg.Password,
			},
		})
		if berr == nil {
			if berr = bootstrapConn.Exec(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", cfg.Database)); berr == nil {
				bootstrapConn.Close()
				// Try connecting again to the target database
				conn, err = clickhouse.Open(&clickhouse.Options{
					Addr: []string{fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)},
					Auth: clickhouse.Auth{
						Database: cfg.Database,
						Username: cfg.Username,
						Password: cfg.Password,
					},
				})
				if err == nil {
					err = conn.Ping(ctx)
				}
			} else {
				bootstrapConn.Close()
			}
		}

		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to ping ClickHouse after bootstrap: %w", err)
		}
	}

	// Create tables
	if err := createTables(ctx, conn); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}

	s := &Store{
		conn:     conn,
		nodeName: nodeName,
		eventCh:  make(chan *SyscallEvent, 10000),
		seen:     make(map[string]bool),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Start background flusher
	s.wg.Add(1)
	go s.flushLoop()

	log.Printf("[Store] Connected to ClickHouse at %s:%d", cfg.Host, cfg.Port)
	return s, nil
}

func createTables(ctx context.Context, conn driver.Conn) error {
	// Events table - stores ONLY blocked events (forensics)
	err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS syscall_events (
			timestamp DateTime64(3),
			namespace LowCardinality(String),
			pod_name String,
			container LowCardinality(String),
			workload_key LowCardinality(String),
			pid UInt32,
			syscall_nr UInt32,
			syscall_name LowCardinality(String),
			argument String,
			comm String,
			cgroup_id UInt64,
			node_name LowCardinality(String),
			action LowCardinality(String)
		) ENGINE = MergeTree()
		PARTITION BY toYYYYMMDD(timestamp)
		ORDER BY (workload_key, syscall_name, argument, timestamp)
		TTL toDateTime(timestamp) + INTERVAL 30 DAY
	`)
	if err != nil {
		return fmt.Errorf("creating syscall_events: %w", err)
	}

	// Counts table - aggregated syscall counts (learned/allowed/observed)
	err = conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS syscall_counts (
			timestamp DateTime,
			workload_key LowCardinality(String),
			syscall_name LowCardinality(String),
			comm String,
			argument String,
			action LowCardinality(String),
			count UInt64,
			node_name LowCardinality(String)
		) ENGINE = SummingMergeTree(count)
		PARTITION BY toYYYYMMDD(timestamp)
		ORDER BY (workload_key, syscall_name, comm, argument, action, timestamp)
		TTL timestamp + INTERVAL 30 DAY
	`)
	if err != nil {
		return fmt.Errorf("creating syscall_counts: %w", err)
	}

	// Allowlist table - stores learned syscalls and patterns per workload
	err = conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS syscall_allowlist (
			workload_key LowCardinality(String),
			template_hash String,
			syscall_name LowCardinality(String),
			argument String,
			is_prefix UInt8 DEFAULT 0,
			training_started DateTime64(3),
			training_period_seconds UInt32,
			first_seen DateTime64(3),
			last_seen DateTime64(3)
		) ENGINE = ReplacingMergeTree(last_seen)
		ORDER BY (workload_key, template_hash, syscall_name, argument, is_prefix)
	`)
	if err != nil {
		return fmt.Errorf("creating syscall_allowlist: %w", err)
	}

	// Audit log table - stores manual policy changes
	err = conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS policy_audit_log (
			timestamp DateTime64(3),
			user_id String,
			workload_key LowCardinality(String),
			action LowCardinality(String),
			syscall_name LowCardinality(String),
			argument String,
			reason String
		) ENGINE = MergeTree()
		ORDER BY (timestamp, workload_key)
	`)
	if err != nil {
		return fmt.Errorf("creating policy_audit_log: %w", err)
	}

	return nil
}

func (s *Store) LogEvent(e *SyscallEvent) {
	s.eventCh <- e
}

func (s *Store) flushLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var events []*SyscallEvent

	for {
		select {
		case <-s.ctx.Done():
			if len(events) > 0 {
				s.flush(events)
			}
			return
		case e := <-s.eventCh:
			events = append(events, e)
			if len(events) >= 1000 {
				s.flush(events)
				events = nil
			}
		case <-ticker.C:
			if len(events) > 0 {
				s.flush(events)
				events = nil
			}
		}
	}
}

func (s *Store) flush(events []*SyscallEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Deduplicate for counts table
	type countKey struct {
		Timestamp   time.Time
		WorkloadKey string
		SyscallName string
		Comm        string
		Argument    string
		Action      string
	}
	countMap := make(map[countKey]*SyscallCount)
	var blockedEvents []*SyscallEvent

	for _, e := range events {
		// Floor to minute for counts
		ts := e.Timestamp.Truncate(time.Minute)
		key := countKey{ts, e.WorkloadKey, e.SyscallName, e.Comm, e.Argument, e.Action}

		if c, ok := countMap[key]; ok {
			c.Count++
		} else {
			countMap[key] = &SyscallCount{
				Timestamp:   ts,
				WorkloadKey: e.WorkloadKey,
				SyscallName: e.SyscallName,
				Comm:        e.Comm,
				Argument:    e.Argument,
				Action:      e.Action,
				Count:       1,
			}
		}

		// Keep blocked events for raw storage
		if e.Action == "blocked" || e.Action == "dry-run-blocked" {
			blockedEvents = append(blockedEvents, e)
		}
	}

	// Insert raw events (blocked only)
	if len(blockedEvents) > 0 {
		batch, err := s.conn.PrepareBatch(ctx, `
			INSERT INTO syscall_events (
				timestamp, namespace, pod_name, container, workload_key, pid, syscall_nr, syscall_name, argument, comm, cgroup_id, node_name, action
			)
		`)
		if err != nil {
			log.Printf("[Store] Failed to prepare events batch: %v", err)
		} else {
			for _, e := range blockedEvents {
				batch.Append(
					e.Timestamp, e.Namespace, e.PodName, e.Container, e.WorkloadKey,
					e.PID, e.SyscallNr, e.SyscallName, e.Argument, e.Comm, e.CgroupID, e.NodeName, e.Action,
				)
			}
			if err := batch.Send(); err != nil {
				log.Printf("[Store] Failed to send events batch: %v", err)
			}
		}
	}

	// Insert aggregated counts
	if len(countMap) > 0 {
		batch, err := s.conn.PrepareBatch(ctx, `
			INSERT INTO syscall_counts (
				timestamp, workload_key, syscall_name, comm, argument, action, count, node_name
			)
		`)
		if err != nil {
			log.Printf("[Store] Failed to prepare counts batch: %v", err)
		} else {
			for _, c := range countMap {
				batch.Append(
					c.Timestamp, c.WorkloadKey, c.SyscallName, c.Comm, c.Argument, c.Action, c.Count, s.nodeName,
				)
			}
			if err := batch.Send(); err != nil {
				log.Printf("[Store] Failed to send counts batch: %v", err)
			}
		}
	}
}

// Close closes the store.
func (s *Store) Close() error {
	s.cancel()
	s.wg.Wait()
	return s.conn.Close()
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// LogPolicyChange records a manual policy change in the audit log.
func (s *Store) LogPolicyChange(entry *PolicyAuditEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	return s.conn.Exec(s.ctx, `
		INSERT INTO policy_audit_log (timestamp, user_id, workload_key, action, syscall_name, argument, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, entry.Timestamp, entry.UserID, entry.WorkloadKey, entry.Action, entry.SyscallName, entry.Argument, entry.Reason)
}

// GetPolicyAudit fetches the manual change history for a workload.
func (s *Store) GetPolicyAudit(workloadKey string) ([]PolicyAuditEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := s.conn.Query(ctx, `
		SELECT timestamp, user_id, workload_key, action, syscall_name, argument, reason
		FROM policy_audit_log
		WHERE workload_key = ?
		ORDER BY timestamp DESC
		LIMIT 100
	`, workloadKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries = []PolicyAuditEntry{}
	for rows.Next() {
		var e PolicyAuditEntry
		if err := rows.Scan(&e.Timestamp, &e.UserID, &e.WorkloadKey, &e.Action, &e.SyscallName, &e.Argument, &e.Reason); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (s *Store) GetGlobalAudit(limit int) ([]PolicyAuditEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := s.conn.Query(ctx, `
		SELECT timestamp, user_id, workload_key, action, syscall_name, argument, reason
		FROM policy_audit_log
		ORDER BY timestamp DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries = []PolicyAuditEntry{}
	for rows.Next() {
		var e PolicyAuditEntry
		if err := rows.Scan(&e.Timestamp, &e.UserID, &e.WorkloadKey, &e.Action, &e.SyscallName, &e.Argument, &e.Reason); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// GetWorkloadBaseline fetches all allowlist entries for a specific workload.
func (s *Store) GetWorkloadBaseline(workloadKey string) ([]AllowlistEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := s.conn.Query(ctx, `
		SELECT workload_key, template_hash, syscall_name, argument, is_prefix, 
		       training_started, training_period_seconds, first_seen, last_seen
		FROM syscall_allowlist
		FINAL
		WHERE workload_key = ?
		ORDER BY last_seen DESC
	`, workloadKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AllowlistEntry
	for rows.Next() {
		var e AllowlistEntry
		var isPrefixVal uint8
		if err := rows.Scan(
			&e.WorkloadKey, &e.TemplateHash, &e.SyscallName, &e.Argument, &isPrefixVal,
			&e.TrainingStarted, &e.TrainingPeriodSeconds, &e.FirstSeen, &e.LastSeen,
		); err != nil {
			continue
		}
		e.IsPrefix = isPrefixVal == 1
		e.Risk = calculateRisk(e.SyscallName, e.Argument)
		entries = append(entries, e)
	}
	return entries, nil
}

// StatsSummary represents high-level metrics.
type StatsSummary struct {
	TotalEvents    uint64 `json:"totalEvents"`
	BlockedEvents  uint64 `json:"blockedEvents"`
	ObservedEvents uint64 `json:"observedEvents"`
	LearnedEvents  uint64 `json:"learnedEvents"`
	HasLearning    bool   `json:"hasLearning"`
}

// GetStatsSummary retrieves aggregated counts from the specified window.
func (s *Store) GetStatsSummary(windowMinutes int) (StatsSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var stats StatsSummary

	// 1. Get volume-based stats from counts table
	rows, err := s.conn.Query(ctx, `
		SELECT action, sum(count) 
		FROM syscall_counts 
		WHERE timestamp > now() - toIntervalMinute(?) 
		GROUP BY action
	`, windowMinutes)
	if err != nil {
		return StatsSummary{}, err
	}
	defer rows.Close()

	for rows.Next() {
		var action string
		var count uint64
		if err := rows.Scan(&action, &count); err != nil {
			continue
		}
		stats.TotalEvents += count
		switch action {
		case "blocked":
			stats.BlockedEvents = count
		case "dry-run-blocked", "observed":
			stats.ObservedEvents += count
		case "learned":
			stats.HasLearning = true
		}
	}

	// 2. Get unique behaviors learned (from allowlist)
	var uniqueLearned uint64
	err = s.conn.QueryRow(ctx, "SELECT count() FROM syscall_allowlist").Scan(&uniqueLearned)
	if err != nil {
		log.Printf("[Store] Failed to count unique learned syscalls: %v", err)
	} else {
		stats.LearnedEvents = uniqueLearned
	}

	return stats, nil
}

// TimeseriesPoint represents a single data point in a chart.
type TimeseriesPoint struct {
	Timestamp time.Time `json:"t"`
	Allowed   uint64    `json:"allowed"`
	Learned   uint64    `json:"learned"`
	Blocked   uint64    `json:"blocked"`
	Observed  uint64    `json:"observed"`
}

// GetTimeseries retrieves time-bucketed event counts.
func (s *Store) GetTimeseries(windowMinutes int) ([]TimeseriesPoint, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Heuristic for bucket size
	intervalMinutes := windowMinutes / 60
	if intervalMinutes < 1 {
		intervalMinutes = 1
	}

	rows, err := s.conn.Query(ctx, `
		SELECT 
			toStartOfInterval(timestamp, toIntervalMinute(?)) as t,
			sumIf(count, action = 'allowed') as allowed,
			sumIf(count, action = 'learned') as learned,
			sumIf(count, action = 'blocked') as blocked,
			sumIf(count, action = 'dry-run-blocked' OR action = 'observed') as observed
		FROM syscall_counts
		WHERE timestamp > now() - toIntervalMinute(?)
		GROUP BY t
		ORDER BY t
	`, intervalMinutes, windowMinutes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TimeseriesPoint
	for rows.Next() {
		var p TimeseriesPoint
		if err := rows.Scan(&p.Timestamp, &p.Allowed, &p.Learned, &p.Blocked, &p.Observed); err != nil {
			continue
		}
		points = append(points, p)
	}
	return points, nil
}

// NamespaceStats represents blocked counts per namespace.
type NamespaceStats struct {
	Namespace     string `json:"namespace"`
	BlockedCount  uint64 `json:"blockedCount"`
	ObservedCount uint64 `json:"observedCount"`
}

// GetTopBlockedNamespaces retrieves namespaces with most blocks in the specified window.
func (s *Store) GetTopBlockedNamespaces(windowMinutes int) ([]NamespaceStats, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := s.conn.Query(ctx, `
		SELECT 
			namespace, 
			sumIf(1, action = 'blocked') as blocked,
			sumIf(1, action = 'dry-run-blocked' OR action = 'observed') as observed
		FROM syscall_events
		WHERE action != 'allowed' AND action != 'learned' AND timestamp > now() - toIntervalMinute(?)
		GROUP BY namespace
		ORDER BY blocked DESC
		LIMIT 5
	`, windowMinutes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []NamespaceStats
	for rows.Next() {
		var ns NamespaceStats
		if err := rows.Scan(&ns.Namespace, &ns.BlockedCount, &ns.ObservedCount); err != nil {
			continue
		}
		stats = append(stats, ns)
	}
	return stats, nil
}

// AddToAllowlist adds a syscall to a workload's allowlist.
func (s *Store) AddToAllowlist(workloadKey, templateHash, syscallName, argument string, isPrefix bool, trainingStarted time.Time, trainingPeriod time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	isPrefixVal := 0
	if isPrefix {
		isPrefixVal = 1
	}

	return s.conn.Exec(ctx, `
		INSERT INTO syscall_allowlist (
			workload_key, template_hash, syscall_name, argument, is_prefix,
			training_started, training_period_seconds, first_seen, last_seen
		) VALUES (?, ?, ?, ?, ?, ?, ?, now(), now())
	`, workloadKey, templateHash, syscallName, argument, isPrefixVal, trainingStarted, uint32(trainingPeriod.Seconds()))
}

// RevokeFromAllowlist removes a policy from the database.
func (s *Store) RevokeFromAllowlist(workloadKey, syscallName, argument string, isPrefix bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	isPrefixVal := 0
	if isPrefix {
		isPrefixVal = 1
	}

	// ClickHouse DELETE is asynchronous usually, but lightweight for ReplacingMergeTree if we target the order key.
	return s.conn.Exec(ctx, `
		ALTER TABLE syscall_allowlist DELETE 
		WHERE workload_key = ? 
		  AND syscall_name = ? 
		  AND argument = ? 
		  AND is_prefix = ?
	`, workloadKey, syscallName, argument, isPrefixVal)
}

// CleanupRedundantRules deletes specific rules (is_prefix=0) that are covered by a new prefix rule.
func (s *Store) CleanupRedundantRules(workloadKey, syscallName, argumentPrefix string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Normalize prefix by stripping trailing '*'
	argumentPrefix = strings.TrimSuffix(argumentPrefix, "*")

	return s.conn.Exec(ctx, `
		ALTER TABLE syscall_allowlist DELETE 
		WHERE workload_key = ? 
		  AND syscall_name = ? 
		  AND is_prefix = 0
		  AND startsWith(argument, ?)
	`, workloadKey, syscallName, argumentPrefix)
}

// ClearBaseline removes all policies for a workload.
func (s *Store) ClearBaseline(workloadKey string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return s.conn.Exec(ctx, `
		ALTER TABLE syscall_allowlist DELETE 
		WHERE workload_key = ?
	`, workloadKey)
}

// GetAllowlist retrieves the allowlist for a workload and its training start time.
func (s *Store) GetAllowlist(workloadKey, templateHash string) ([]AllowlistEntry, time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	query := `
		SELECT 
			workload_key, template_hash, syscall_name, argument, is_prefix,
			training_started, training_period_seconds, first_seen, last_seen
		FROM syscall_allowlist
		FINAL
		WHERE workload_key = ?
	`
	args := []interface{}{workloadKey}

	if templateHash != "" {
		query += " AND template_hash = ?"
		args = append(args, templateHash)
	}

	rows, err := s.conn.Query(ctx, query, args...)
	if err != nil {
		log.Printf("[Store] Failed to query allowlist for %s: %v", workloadKey, err)
		return nil, time.Time{}
	}
	defer rows.Close()

	var entries []AllowlistEntry
	var trainingStarted time.Time

	for rows.Next() {
		var e AllowlistEntry
		var isPrefixVal uint8
		if err := rows.Scan(
			&e.WorkloadKey, &e.TemplateHash, &e.SyscallName, &e.Argument, &isPrefixVal,
			&e.TrainingStarted, &e.TrainingPeriodSeconds, &e.FirstSeen, &e.LastSeen,
		); err != nil {
			continue
		}
		e.IsPrefix = isPrefixVal == 1
		e.Risk = calculateRisk(e.SyscallName, e.Argument)
		entries = append(entries, e)
		if trainingStarted.IsZero() {
			trainingStarted = e.TrainingStarted
		}
	}
	return entries, trainingStarted
}

// GetAllAllowlists retrieves all allowlists from the store on startup.
func (s *Store) GetAllAllowlists() (map[string][]AllowlistEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := s.conn.Query(ctx, `
		SELECT 
			workload_key, template_hash, syscall_name, argument, is_prefix,
			training_started, training_period_seconds, first_seen, last_seen
		FROM syscall_allowlist
		FINAL
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]AllowlistEntry)
	for rows.Next() {
		var e AllowlistEntry
		var isPrefixVal uint8
		if err := rows.Scan(
			&e.WorkloadKey, &e.TemplateHash, &e.SyscallName, &e.Argument, &isPrefixVal,
			&e.TrainingStarted, &e.TrainingPeriodSeconds, &e.FirstSeen, &e.LastSeen,
		); err != nil {
			continue
		}
		e.IsPrefix = isPrefixVal == 1
		result[e.WorkloadKey] = append(result[e.WorkloadKey], e)
	}
	return result, nil
}

// Detection represents a security event from ClickHouse.
type Detection struct {
	ID          string
	Timestamp   time.Time
	Namespace   string
	PodName     string
	WorkloadKey string
	SyscallName string
	Argument    string
	Comm        string
	Action      string
	Risk        string
	IsPrefix    bool
	Count       int64
	LastSeen    time.Time
}

// GetDetections retrieves recent security events within a time window with pagination, search and optional grouping.
func (s *Store) GetDetections(limit int, offset int, windowMinutes int, search string, grouped bool) ([]Detection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var query string
	if grouped {
		query = `
			SELECT 
				max(toString(timestamp) || workload_key || syscall_name) as id,
				max(timestamp) as event_time, namespace, '' as pod_name, workload_key, syscall_name, argument, comm, action,
				count() as count,
				max(timestamp) as last_seen
			FROM syscall_events
			WHERE (action = 'blocked' OR action = 'dry-run-blocked')
			  AND timestamp > now() - toIntervalMinute(?)
		`
	} else {
		query = `
			SELECT 
				toString(timestamp) || workload_key || syscall_name as id,
				timestamp as event_time, namespace, pod_name, workload_key, syscall_name, argument, comm, action,
				1 as count,
				timestamp as last_seen
			FROM syscall_events
			WHERE (action = 'blocked' OR action = 'dry-run-blocked')
			  AND timestamp > now() - toIntervalMinute(?)
		`
	}
	args := []interface{}{windowMinutes}

	if search != "" {
		query += ` AND (
			ilike(workload_key, ?) OR 
			ilike(syscall_name, ?) OR 
			ilike(argument, ?) OR 
			ilike(comm, ?) OR 
			ilike(namespace, ?)
		)`
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
	}

	if grouped {
		query += ` GROUP BY namespace, workload_key, syscall_name, argument, comm, action `
	}

	query += ` ORDER BY event_time DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var detections []Detection
	for rows.Next() {
		var d Detection
		if err := rows.Scan(
			&d.ID, &d.Timestamp, &d.Namespace, &d.PodName, &d.WorkloadKey,
			&d.SyscallName, &d.Argument, &d.Comm, &d.Action, &d.Count, &d.LastSeen,
		); err != nil {
			continue
		}
		d.Risk = calculateRisk(d.SyscallName, d.Argument)
		detections = append(detections, d)
	}
	return detections, nil
}

// CountDetections returns the total number of detections in the time window matching search and optional grouping.
func (s *Store) CountDetections(windowMinutes int, search string, grouped bool) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var query string
	if grouped {
		query = `
			SELECT count() FROM (
				SELECT 1
				FROM syscall_events
				WHERE (action = 'blocked' OR action = 'dry-run-blocked')
				  AND timestamp > now() - toIntervalMinute(?)
		`
	} else {
		query = `
			SELECT count()
			FROM syscall_events
			WHERE (action = 'blocked' OR action = 'dry-run-blocked')
			  AND timestamp > now() - toIntervalMinute(?)
		`
	}
	args := []interface{}{windowMinutes}

	if search != "" {
		query += ` AND (
			ilike(workload_key, ?) OR 
			ilike(syscall_name, ?) OR 
			ilike(argument, ?) OR 
			ilike(comm, ?) OR 
			ilike(namespace, ?)
		)`
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
	}

	if grouped {
		query += ` GROUP BY namespace, workload_key, syscall_name, argument, comm, action ) `
	}

	var count uint64
	err := s.conn.QueryRow(ctx, query, args...).Scan(&count)

	return int64(count), err
}

// GetLearningQueue retrieves recent learned events (normalized behavioral patterns).
func (s *Store) GetLearningQueue(limit int) ([]Detection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Updated to query syscall_allowlist which now holds the normalized behavioral patterns
	rows, err := s.conn.Query(ctx, `
		SELECT 
			workload_key || ':' || syscall_name || ':' || argument as id,
			last_seen as timestamp,
			splitByChar('/', workload_key)[2] as namespace,
			'' as pod_name,
			workload_key,
			syscall_name,
			argument,
			'learned' as action,
			is_prefix
		FROM syscall_allowlist
		FINAL
		WHERE training_started IS NOT NULL
		ORDER BY last_seen DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var detections []Detection
	for rows.Next() {
		var d Detection
		var isPrefixVal uint8
		if err := rows.Scan(
			&d.ID, &d.Timestamp, &d.Namespace, &d.PodName, &d.WorkloadKey,
			&d.SyscallName, &d.Argument, &d.Action, &isPrefixVal,
		); err != nil {
			continue
		}
		d.IsPrefix = isPrefixVal == 1
		d.Risk = calculateRisk(d.SyscallName, d.Argument)
		detections = append(detections, d)
	}
	return detections, nil
}

func calculateRisk(syscall, argument string) string {
	// Simple heuristic for now
	criticalSyscalls := map[string]bool{
		"execve":  true,
		"ptrace":  true,
		"reboot":  true,
		"mount":   true,
		"setuid":  true,
		"setgid":  true,
		"socket":  true,
		"connect": true,
		"bind":    true,
	}

	if criticalSyscalls[syscall] {
		return "high"
	}

	sensitivePaths := []string{"/etc/shadow", "/etc/passwd", "/root", "/proc/kcore", "/dev/mem"}
	for _, p := range sensitivePaths {
		if contains(argument, p) {
			return "high"
		}
	}

	if contains(argument, "/etc/") || contains(argument, "/var/run/secrets/") {
		return "medium"
	}

	return "low"
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > 0 && len(substr) > 0 && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr)))
}
