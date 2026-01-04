// Package engine provides the core syscall enforcement engine for KubeSec.
// It orchestrates eBPF tracing, K8s workload discovery, and ClickHouse storage.
package engine

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kubesec/kubesec/pkg/api"
	"github.com/kubesec/kubesec/pkg/ebpf"
	"github.com/kubesec/kubesec/pkg/resolver"
	"github.com/kubesec/kubesec/pkg/store"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

// Engine is the core enforcement engine.
type Engine struct {
	tracer    *ebpf.Tracer
	resolver  *resolver.K8sResolver
	store     *store.Store
	workloads *WorkloadCache
	recorder  record.EventRecorder
	api       *api.Server
	be        *BehavioralEngine

	// In-memory allowlist cache for hot path (no DB queries per syscall)
	allowlists   map[string]*AllowlistCache // workloadKey -> cache
	allowlistsMu sync.RWMutex

	// Discovery
	discoveryChan chan bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// AllowlistCache holds the in-memory allowlist for a workload.
type AllowlistCache struct {
	mu              sync.RWMutex
	TrainingStarted time.Time
	TemplateHash    string
	Entries         map[string]bool // "syscall:argument" -> allowed
	PrefixEntries   map[string]bool // "syscall:prefix" -> allowed
}

// Config holds engine configuration.
type Config struct {
	ClickHouseHost string
	ClickHousePort int
	QuietMode      bool
	EnableTracing  bool
}

// New creates a new enforcement engine.
func New(cfg Config) (*Engine, error) {
	ctx, cancel := context.WithCancel(context.Background())

	var tracer *ebpf.Tracer
	var err error

	// Initialize eBPF tracer only if enabled
	if cfg.EnableTracing {
		tracer, err = ebpf.NewTracer()
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create tracer: %w", err)
		}
	} else {
		log.Println("[Engine] Tracing disabled (Server Mode)")
	}

	// Initialize K8s resolver
	k8sResolver, err := resolver.NewK8sResolver()
	if err != nil {
		tracer.Close()
		cancel()
		return nil, fmt.Errorf("failed to create k8s resolver: %w", err)
	}

	// Initialize ClickHouse store
	storeCfg := store.Config{
		Host: cfg.ClickHouseHost,
		Port: cfg.ClickHousePort,
	}
	clickhouseStore, err := store.New(storeCfg)
	if err != nil {
		tracer.Close()
		cancel()
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	// Initialize workload cache
	workloadCache, err := NewWorkloadCache()
	if err != nil {
		clickhouseStore.Close()
		tracer.Close()
		cancel()
		return nil, fmt.Errorf("failed to create workload cache: %w", err)
	}

	// Initialize event recorder
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartStructuredLogging(0)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: k8sResolver.GetClient().CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "kubesec-agent"})

	e := &Engine{
		tracer:        tracer,
		resolver:      k8sResolver,
		store:         clickhouseStore,
		workloads:     workloadCache,
		recorder:      recorder,
		be:            NewBehavioralEngine(),
		allowlists:    make(map[string]*AllowlistCache),
		discoveryChan: make(chan bool, 1),
		ctx:           ctx,
		cancel:        cancel,
	}

	// Initialize API server
	e.api = api.NewServer(e)

	// Set up workload cache callbacks
	workloadCache.OnChange(e.handleWorkloadChange)

	return e, nil
}

// Start begins the engine's event processing loop.
func (e *Engine) Start() error {
	log.Printf("[Engine] Starting KubeSec Agent v0.2.3 (Logging Noise Reduction)...")
	// Load existing allowlists from ClickHouse
	if err := e.loadAllowlistsFromDB(); err != nil {
		log.Printf("[Engine] Warning: failed to load allowlists from DB: %v", err)
	}

	// Start workload cache (K8s informers)
	if err := e.workloads.Start(e.ctx); err != nil {
		return fmt.Errorf("failed to start workload cache: %w", err)
	}

	// Start discovery worker only if tracing is enabled
	if e.tracer != nil {
		e.wg.Add(1)
		go e.discoveryWorker()

		// Request initial discovery
		e.requestDiscovery()

		// Start periodic container discovery
		e.wg.Add(1)
		go e.containerDiscoveryLoop()
	}

	// Start periodic allowlist sync from ClickHouse
	e.wg.Add(1)
	go e.snapshotSyncLoop()

	// Start event processing
	e.wg.Add(1)
	go e.eventLoop()

	// Start API server
	if err := e.api.Start(8080); err != nil {
		return fmt.Errorf("failed to start api server: %w", err)
	}

	log.Println("[Engine] API server started on :8080")
	return nil
}

// Stop gracefully shuts down the engine.
func (e *Engine) Stop() {
	log.Println("[Engine] Stopping...")

	// Cancel context to signal all goroutines to stop
	e.cancel()

	// Close tracer first to unblock ReadEvent() in eventLoop
	// This is critical - the ring buffer reader blocks indefinitely
	// and won't respect context cancellation
	if e.tracer != nil {
		log.Println("[Engine] Closing eBPF tracer...")
		e.tracer.Close()
	}

	// Wait for all goroutines to finish
	log.Println("[Engine] Waiting for goroutines...")
	e.wg.Wait()

	// Stop API server
	log.Println("[Engine] Stopping API server...")
	e.api.Stop()

	// Close store
	log.Println("[Engine] Closing store...")
	e.store.Close()

	log.Println("[Engine] Stopped successfully")
}

// eventLoop processes eBPF syscall events.
func (e *Engine) eventLoop() {
	defer e.wg.Done()

	if e.tracer == nil {
		return
	}

	for {
		select {
		case <-e.ctx.Done():
			return
		default:
		}

		event, err := e.tracer.ReadEvent()
		if err != nil {
			if e.ctx.Err() != nil {
				return
			}
			continue
		}

		e.handleSyscallEvent(event)
	}
}

// handleSyscallEvent processes a single syscall event.
func (e *Engine) handleSyscallEvent(event *ebpf.SyscallEvent) {
	// Resolve pod info
	podInfo := e.resolver.ResolveCgroupID(event.CgroupID)
	if podInfo == nil {
		// Try PID-based resolution as fallback
		podInfo = e.resolver.ResolvePID(event.Tgid)
		if podInfo != nil {
			e.resolver.RegisterCgroupID(event.CgroupID, podInfo.ContainerID)
		}
	}

	if podInfo == nil {
		return // Unknown container, skip
	}

	// Get workload key
	workloadKey := fmt.Sprintf("%s/%s/%s", podInfo.OwnerKind, podInfo.Namespace, podInfo.OwnerName)

	// Get syscall name and argument
	syscallName := e.tracer.GetSyscallName(event.SyscallNr)
	argument := strings.TrimRight(string(event.ArgStr[:]), "\x00")

	// Check global allowlist (noise reduction)
	if e.tracer.IsGlobalAllowlisted(syscallName) {
		// Ensure it's allowed in kernel for this cgroup
		e.tracer.AllowSyscall(event.CgroupID, int(event.SyscallNr), "")
		return
	}

	// Check if workload is secured
	workloadInfo := e.workloads.Get(workloadKey)
	if workloadInfo == nil || !workloadInfo.Secure {
		return // Not secured, skip tracking entirely
	}

	// Secured workload - check training vs enforcement
	e.allowlistsMu.RLock()
	cache := e.allowlists[workloadKey]
	e.allowlistsMu.RUnlock()

	// Initialize cache if needed
	if cache == nil || cache.TemplateHash != workloadInfo.TemplateHash {
		cache = e.initAllowlistCache(workloadKey, workloadInfo)
	}

	// Check if still in training
	isTraining := cache.TrainingStarted.IsZero() || time.Since(cache.TrainingStarted) < workloadInfo.TrainingPeriod

	// Numeric cache key for stability throughout map expansions
	allowlistKey := fmt.Sprintf("%d:%s", event.SyscallNr, argument)
	allowed := e.checkAllowance(cache, int(event.SyscallNr), argument)

	var action string
	if isTraining {
		// Training mode: learn new syscalls or patterns
		if !allowed {
			persist, isPrefix, generalizedArg := e.be.ProcessEvent(workloadKey, syscallName, argument)
			if !persist {
				return // Deduplicated event, skip
			}

			// Add to cache
			cache.mu.Lock()
			if isPrefix {
				if cache.PrefixEntries == nil {
					cache.PrefixEntries = make(map[string]bool)
				}
				prefixKey := fmt.Sprintf("%d:%s", event.SyscallNr, generalizedArg)
				cache.PrefixEntries[prefixKey] = true
			} else {
				cache.Entries[allowlistKey] = true
			}
			cache.mu.Unlock()

			// Log learned syscall/pattern to store
			_ = e.store.AddToAllowlist(workloadKey, workloadInfo.TemplateHash, syscallName, generalizedArg, isPrefix, cache.TrainingStarted, workloadInfo.TrainingPeriod)

			// Update kernel-side allowlist for this cgroup
			if isPrefix {
				_ = e.tracer.AllowPrefix(event.CgroupID, int(event.SyscallNr), generalizedArg)
			} else {
				_ = e.tracer.AllowSyscall(event.CgroupID, int(event.SyscallNr), argument)
			}
		}
		action = "learned"
	} else {
		// Enforcement mode
		if allowed {
			action = "allowed"
		} else {
			// If not allowed, determine if we should block or just log
			// We only physically block if:
			// 1. DryRun is false
			// 2. Training is over
			// 3. AND the training period was explicitly set (safety transition to dry-run)
			shouldBlock := !workloadInfo.DryRun && !isTraining && workloadInfo.ExplicitPeriod

			if !shouldBlock {
				action = "dry-run-blocked"
				log.Printf("[DRY-RUN] %s syscall=%s arg=%s pod=%s/%s pid=%d (Flags: dr=%v tr=%v ex=%v)",
					workloadKey, syscallName, argument, podInfo.Namespace, podInfo.PodName, event.Tgid,
					workloadInfo.DryRun, isTraining, workloadInfo.ExplicitPeriod)
				e.recorder.Eventf(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: podInfo.PodName, Namespace: podInfo.Namespace}}, corev1.EventTypeWarning, "SyscallDryRun", "Syscall %s (%s) would be blocked (Dry-Run) [dr=%v,tr=%v,ex=%v]", syscallName, argument, workloadInfo.DryRun, isTraining, workloadInfo.ExplicitPeriod)
			} else {
				action = "blocked"
				// Kernel should have already killed it if enforcement was enabled,
				// but we keep this as fallback and for logging.
				log.Printf("[BLOCKED] %s syscall=%s arg=%s pod=%s/%s pid=%d",
					workloadKey, syscallName, argument, podInfo.Namespace, podInfo.PodName, event.Tgid)
				e.recorder.Eventf(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: podInfo.PodName, Namespace: podInfo.Namespace}}, corev1.EventTypeWarning, "SyscallBlocked", "Process killed for unauthorized syscall %s (%s)", syscallName, argument)
				e.killProcess(int(event.Tgid))
			}
		}

		// Ensure kernel-side enforcement is enabled for this cgroup ONLY if all conditions are met
		enforce := !workloadInfo.DryRun && !isTraining && workloadInfo.ExplicitPeriod
		if enforce {
			e.tracer.EnableEnforcement(event.CgroupID)
		} else {
			// If in training, dry-run, or default 24h transition, ensure kernel-side enforcement is disabled.
			e.tracer.DisableEnforcement(event.CgroupID)
		}
	}

	// Log the event (only if it's a security event - blocked or dry-run)
	if action == "blocked" || action == "dry-run-blocked" {
		e.store.LogEvent(&store.SyscallEvent{
			Timestamp:   time.Now(),
			Namespace:   podInfo.Namespace,
			PodName:     podInfo.PodName,
			Container:   podInfo.Container,
			WorkloadKey: workloadKey,
			PID:         event.Tgid,
			SyscallNr:   uint32(event.SyscallNr),
			SyscallName: syscallName,
			Argument:    argument,
			Comm:        strings.TrimRight(string(event.Comm[:]), "\x00"),
			CgroupID:    event.CgroupID,
			Action:      action,
		})
	}
}

// checkAllowance checks if a syscall is allowed by exact match or prefix.
func (e *Engine) checkAllowance(cache *AllowlistCache, nr int, arg string) bool {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	// 1. Exact match
	key := fmt.Sprintf("%d:%s", nr, arg)
	if cache.Entries[key] {
		return true
	}

	// 2. Prefix match
	if len(cache.PrefixEntries) > 0 {
		for pKey := range cache.PrefixEntries {
			// pKey format: "nr:prefix"
			parts := strings.SplitN(pKey, ":", 2)
			if len(parts) == 2 && parts[0] == fmt.Sprintf("%d", nr) {
				prefix := parts[1]
				if strings.HasPrefix(arg, prefix) {
					return true
				}
			}
		}
	}

	return false
}

// initAllowlistCache initializes or resets the allowlist cache for a workload.
func (e *Engine) initAllowlistCache(workloadKey string, info *WorkloadInfo) *AllowlistCache {
	e.allowlistsMu.Lock()
	defer e.allowlistsMu.Unlock()
	return e.initAllowlistCacheLocked(workloadKey, info)
}

// initAllowlistCacheLocked initializes the cache. Caller MUST hold e.allowlistsMu.Lock().
func (e *Engine) initAllowlistCacheLocked(workloadKey string, info *WorkloadInfo) *AllowlistCache {
	// If already exists, update/validate from current manifest
	if existing, ok := e.allowlists[workloadKey]; ok {
		existing.mu.Lock()
		// If TemplateHash changed, we might want to do something, but for now
		// we keep the policies as per user request (no reset on rollout).
		existing.TemplateHash = info.TemplateHash
		existing.mu.Unlock()
		return existing
	}

	// Check if we have existing entries in DB for this template hash
	entries, trainingStarted := e.store.GetAllowlist(workloadKey, info.TemplateHash)

	cache := &AllowlistCache{
		TrainingStarted: trainingStarted,
		TemplateHash:    info.TemplateHash,
		Entries:         make(map[string]bool),
		PrefixEntries:   make(map[string]bool),
	}

	// If no existing training time, start now
	if cache.TrainingStarted.IsZero() {
		cache.TrainingStarted = time.Now()
	}

	// Load existing entries
	for _, entry := range entries {
		nr, err := e.tracer.GetSyscallNr(entry.SyscallName)
		if err != nil {
			continue
		}
		if entry.IsPrefix {
			entry.Argument = strings.TrimSuffix(entry.Argument, "*")
		}
		key := fmt.Sprintf("%d:%s", nr, entry.Argument)
		if entry.IsPrefix {
			cache.PrefixEntries[key] = true
		} else {
			cache.Entries[key] = true
		}
	}

	e.allowlists[workloadKey] = cache

	log.Printf("[Engine] Initialized allowlist for %s: %d entries, %d prefixes, training=%v",
		workloadKey, len(cache.Entries), len(cache.PrefixEntries), time.Since(cache.TrainingStarted) < info.TrainingPeriod)

	return cache
}

// loadAllowlistsFromDB loads all allowlists from ClickHouse on startup.
func (e *Engine) loadAllowlistsFromDB() error {
	allowlists, err := e.store.GetAllAllowlists()
	if err != nil {
		return err
	}

	e.allowlistsMu.Lock()
	defer e.allowlistsMu.Unlock()

	for workloadKey, entries := range allowlists {
		if len(entries) == 0 {
			continue
		}

		// Get training info from first entry
		trainingStarted := entries[0].TrainingStarted
		// trainingPeriod := time.Duration(entries[0].TrainingPeriodSeconds) * time.Second // Removed, now from WorkloadInfo
		templateHash := entries[0].TemplateHash

		cache := &AllowlistCache{
			TrainingStarted: trainingStarted,
			// TrainingPeriod:  trainingPeriod, // Removed
			TemplateHash: templateHash,
			// Note: DryRun and ExplicitPeriod will be updated by the informer's first
			// handleWorkloadChange call or when initAllowlistCache is called.
			Entries: make(map[string]bool),
		}

		for _, entry := range entries {
			nr, err := e.tracer.GetSyscallNr(entry.SyscallName)
			if err != nil {
				continue
			}
			if entry.IsPrefix {
				entry.Argument = strings.TrimSuffix(entry.Argument, "*")
			}
			key := fmt.Sprintf("%d:%s", nr, entry.Argument)
			if entry.IsPrefix {
				if cache.PrefixEntries == nil {
					cache.PrefixEntries = make(map[string]bool)
				}
				cache.PrefixEntries[key] = true
			} else {
				cache.Entries[key] = true
			}
		}

		e.allowlists[workloadKey] = cache
		log.Printf("[Engine] Loaded allowlist for %s: %d entries", workloadKey, len(cache.Entries))
	}

	return nil
}

// handleWorkloadChange is called when a workload's configuration changes.
func (e *Engine) handleWorkloadChange(workloadKey string, info *WorkloadInfo) {
	log.Printf("[Engine] %s: Workload change detected (Secure: %v, DryRun: %v)", workloadKey, info.Secure, info.DryRun)

	e.allowlistsMu.Lock()
	existing := e.allowlists[workloadKey]

	// Versioning removed: we no longer reset training on template hash changes.
	// This ensures policy persists across all rollouts.

	// Update or initialize cache
	if !info.Secure {
		delete(e.allowlists, workloadKey)
	} else if existing != nil {
		existing.mu.Lock()
		// Reset training clock if we are manually switching BACK to dry-run (learning) from non-dry-run
		if info.DryRun && !info.ExplicitPeriod && info.TrainingPeriod > 0 {
			// This is a bit complex: we want to reset if the user intends to restart learning.
			// For now, let's reset if it was previously NOT dry-run OR if the period is freshly set.
			existing.TrainingStarted = time.Now()
			log.Printf("[Engine] %s: Re-initialized training period start time", workloadKey)
		}
		existing.TemplateHash = info.TemplateHash
		existing.mu.Unlock()
	}
	e.allowlistsMu.Unlock()

	// Request discovery to update eBPF maps
	e.requestDiscovery()
}

func (e *Engine) requestDiscovery() {
	select {
	case e.discoveryChan <- true:
	default:
		// Already a discovery queued
	}
}

func (e *Engine) discoveryWorker() {
	defer e.wg.Done()
	log.Println("[Engine] Discovery worker started")
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.discoveryChan:
			// Debounce/Throttling: wait a bit for more changes
			time.Sleep(100 * time.Millisecond)
			// Drain any additional requests
			select {
			case <-e.discoveryChan:
			default:
			}

			if err := e.discoverContainers(); err != nil {
				log.Printf("[Engine] Discovery error: %v", err)
			}
		}
	}
}

// discoverContainers finds and monitors K8s containers.
func (e *Engine) discoverContainers() error {
	containers, err := e.resolver.DiscoverContainers()
	if err != nil {
		return err
	}

	for _, c := range containers {
		if c.CgroupID != 0 {
			// Only monitor if the workload is secured
			workloadKey := fmt.Sprintf("%s/%s/%s", c.OwnerKind, c.Namespace, c.OwnerName)
			workloadInfo := e.workloads.Get(workloadKey)

			if workloadInfo != nil && workloadInfo.Secure {
				if err := e.tracer.AddTargetCgroup(c.CgroupID); err != nil {
					log.Printf("[Engine] Failed to add cgroup %d: %v", c.CgroupID, err)
					continue
				}

				// Sync allowlist to kernel for this cgroup
				e.allowlistsMu.RLock()
				cache := e.allowlists[workloadKey]
				e.allowlistsMu.RUnlock()
				if cache != nil {
					e.syncKernelAllowlist(c.CgroupID, cache, workloadInfo)
				}

				log.Printf("[Engine] Monitoring: %s/%s/%s (cgroup: %d)",
					c.Namespace, c.PodName, c.Container, c.CgroupID)
			} else {
				// Ensure it's not being monitored if not secure
				e.tracer.RemoveTargetCgroup(c.CgroupID)
			}
		}
	}

	return nil
}

// containerDiscoveryLoop periodically discovers new containers.
func (e *Engine) containerDiscoveryLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.discoverContainers()
		}
	}
}

// killProcess sends SIGKILL to a specific process.
// This kills only the offending process, not the entire container.
func (e *Engine) killProcess(pid int) {
	// Use os.Process to send SIGKILL
	proc, err := os.FindProcess(pid)
	if err != nil {
		log.Printf("[Engine] Failed to find process %d: %v", pid, err)
		return
	}
	if err := proc.Kill(); err != nil {
		log.Printf("[Engine] Failed to kill process %d: %v", pid, err)
	}
}

// syncKernelAllowlist syncs the in-memory allowlist to the eBPF map for a specific cgroup.
func (e *Engine) syncKernelAllowlist(cgroupID uint64, cache *AllowlistCache, info *WorkloadInfo) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	// First, allow all global syscalls
	for syscallName := range ebpf.GlobalAllowlist {
		syscallNr, err := e.tracer.GetSyscallNr(syscallName)
		if err == nil {
			e.tracer.AllowSyscall(cgroupID, syscallNr, "")
		}
	}

	for key := range cache.Entries {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			continue
		}
		syscallNrStr := parts[0]
		argument := parts[1]

		var nr int
		_, err := fmt.Sscanf(syscallNrStr, "%d", &nr)
		if err != nil {
			log.Printf("[Engine] Invalid numeric key in cache: %s", key)
			continue
		}

		err = e.tracer.AllowSyscall(cgroupID, nr, argument)
		if err != nil {
			log.Printf("[Engine] Failed to push %s to kernel: %v", key, err)
		}
	}

	for key := range cache.PrefixEntries {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			continue
		}
		syscallNrStr := parts[0]
		prefix := parts[1]

		var nr int
		_, err := fmt.Sscanf(syscallNrStr, "%d", &nr)
		if err == nil {
			_ = e.tracer.AllowPrefix(cgroupID, nr, prefix)
			log.Printf("[Engine] Pushed prefix nr=%d path=%s* to kernel for cgroup %d", nr, prefix, cgroupID)
		}
	}

	// Update enforcement mode in kernel
	// Determine if still in learning
	isTraining := cache.TrainingStarted.IsZero() || time.Since(cache.TrainingStarted) < info.TrainingPeriod

	// We only enforce if: 1. Training is over, 2. Dry-run is false, 3. AND the period was explicitly set.
	enforce := !isTraining && !info.DryRun && info.ExplicitPeriod
	if enforce {
		e.tracer.EnableEnforcement(cgroupID)
	} else {
		e.tracer.DisableEnforcement(cgroupID)
	}
}

// snapshotSyncLoop periodically pulls allowlists from ClickHouse to stay in sync with the SOC team's changes.
func (e *Engine) snapshotSyncLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			if err := e.loadAllowlistsFromDB(); err != nil {
				log.Printf("[Engine] Sync failed: %v", err)
			} else {
				// After loading from DB, we need to re-sync the kernel maps for all active containers
				e.discoverContainers()
			}
		}
	}
}

// GetWorkloads returns the current status of all monitored workloads.
// Implements api.EngineInterface.
func (e *Engine) GetWorkloads() []api.WorkloadStatus {
	e.workloads.mu.RLock()
	defer e.workloads.mu.RUnlock()

	result := []api.WorkloadStatus{}

	for id, info := range e.workloads.workloads {
		status := "unmonitored"
		if info.Secure {
			// Determine status based on config and cache
			e.allowlistsMu.RLock()
			cache := e.allowlists[id]
			e.allowlistsMu.RUnlock()

			// If training period is zero, it's always enforcing/observing
			if info.TrainingPeriod == 0 {
				if info.DryRun {
					status = "observing"
				} else {
					status = "enforcing"
				}
			} else {
				// Determine if we are still in learning phase
				isLearning := info.DryRun
				if !isLearning && cache != nil {
					isLearning = cache.TrainingStarted.IsZero() || time.Since(cache.TrainingStarted) < info.TrainingPeriod
				} else if !isLearning {
					isLearning = true
				}

				if isLearning {
					status = "learning"
				} else {
					// Learning is over. Determine if we are observing or enforcing.
					// We only enforce if dry-run is off AND it was an explicit period.
					if info.DryRun || !info.ExplicitPeriod {
						status = "observing"
					} else {
						status = "enforcing"
					}
				}
			}
		}

		progress := 0
		if status == "enforcing" || status == "observing" {
			// If we transitioned out of learning, progress is 100%
			if info.TrainingPeriod > 0 {
				progress = 100
			}
		} else if status == "learning" {
			e.allowlistsMu.RLock()
			cache := e.allowlists[id]
			e.allowlistsMu.RUnlock()
			if cache != nil && !cache.TrainingStarted.IsZero() && info.TrainingPeriod > 0 {
				elapsed := time.Since(cache.TrainingStarted)
				progress = int((elapsed.Seconds() / info.TrainingPeriod.Seconds()) * 100)
				if progress > 100 {
					progress = 100
				}
			}
		}

		result = append(result, api.WorkloadStatus{
			ID:               id,
			Name:             info.Name,
			Namespace:        info.Namespace,
			Kind:             info.Kind,
			Status:           status,
			TrainingProgress: progress,
			TemplateHash:     info.TemplateHash,
			Secure:           info.Secure,
			DryRun:           info.DryRun,
			LastSync:         time.Now(), // Placeholder
			Replicas:         1,          // Placeholder
			PolicyVersion:    "v1",       // Placeholder
		})
	}

	return result
}

// GetStatsSummary retrieves aggregated metrics from the store.
// Implements api.EngineInterface.
func (e *Engine) GetStatsSummary(windowMinutes int) (api.StatsSummary, error) {
	stats, err := e.store.GetStatsSummary(windowMinutes)
	if err != nil {
		return api.StatsSummary{}, err
	}
	return api.StatsSummary{
		ClusterName:    e.workloads.GetClusterName(),
		TotalEvents:    stats.TotalEvents,
		BlockedEvents:  stats.BlockedEvents,
		ObservedEvents: stats.ObservedEvents,
		LearnedEvents:  stats.LearnedEvents,
		NodeCount:      e.resolver.GetNodeCount(),
		NamespaceCount: e.resolver.GetNamespaceCount(),
	}, nil
}

// GetTimeseries retrieves time-bucketed event counts from the store.
// Implements api.EngineInterface.
func (e *Engine) GetTimeseries(windowMinutes int) ([]api.TimeseriesPoint, error) {
	points, err := e.store.GetTimeseries(windowMinutes)
	if err != nil {
		return nil, err
	}

	result := make([]api.TimeseriesPoint, len(points))
	for i, p := range points {
		result[i] = api.TimeseriesPoint{
			Timestamp: p.Timestamp,
			Allowed:   p.Allowed,
			Learned:   p.Learned,
			Blocked:   p.Blocked,
			Observed:  p.Observed,
		}
	}
	return result, nil
}

// GetTopNamespaces retrieves namespaces with most blocks.
// Implements api.EngineInterface.
func (e *Engine) GetTopNamespaces(windowMinutes int) ([]api.NamespaceStats, error) {
	stats, err := e.store.GetTopBlockedNamespaces(windowMinutes)
	if err != nil {
		return nil, err
	}

	result := make([]api.NamespaceStats, len(stats))
	for i, s := range stats {
		result[i] = api.NamespaceStats{
			Namespace:     s.Namespace,
			BlockedCount:  s.BlockedCount,
			ObservedCount: s.ObservedCount,
		}
	}
	return result, nil
}

// GetDetections retrieves recent security events from the store.
// Implements api.EngineInterface.
func (e *Engine) GetDetections(limit int, offset int, windowMinutes int, search string, grouped bool) ([]api.Detection, error) {
	detections, err := e.store.GetDetections(limit, offset, windowMinutes, search, grouped)
	if err != nil {
		return nil, err
	}

	result := make([]api.Detection, len(detections))
	for i, d := range detections {
		result[i] = api.Detection{
			ID:          d.ID,
			Timestamp:   d.Timestamp,
			Namespace:   d.Namespace,
			PodName:     d.PodName,
			WorkloadKey: d.WorkloadKey,
			SyscallName: d.SyscallName,
			Argument:    d.Argument,
			Comm:        d.Comm,
			Action:      d.Action,
			Risk:        d.Risk,
			IsPrefix:    d.IsPrefix,
			Count:       d.Count,
			LastSeen:    d.LastSeen,
		}
	}
	return result, nil
}

// CountDetections returns the total number of detections.
func (e *Engine) CountDetections(windowMinutes int, search string, grouped bool) (int64, error) {
	return e.store.CountDetections(windowMinutes, search, grouped)
}

// GetLearningQueue retrieves recent learned events from the store.
// Implements api.EngineInterface.
func (e *Engine) GetLearningQueue(limit int) ([]api.Detection, error) {
	detections, err := e.store.GetLearningQueue(limit)
	if err != nil {
		return nil, err
	}

	result := make([]api.Detection, len(detections))
	for i, d := range detections {
		result[i] = api.Detection{
			ID:          d.ID,
			Timestamp:   d.Timestamp,
			Namespace:   d.Namespace,
			PodName:     d.PodName,
			WorkloadKey: d.WorkloadKey,
			SyscallName: d.SyscallName,
			Argument:    d.Argument,
			Comm:        d.Comm,
			Action:      d.Action,
			Risk:        d.Risk,
			IsPrefix:    d.IsPrefix,
		}
	}
	return result, nil
}

// cleanupRedundantRulesLocked removes specific rules covered by a prefix.
// Caller MUST hold e.allowlistsMu.Lock().
func (e *Engine) cleanupRedundantRulesLocked(workloadKey, syscallName, argumentPrefix string) error {
	cache := e.allowlists[workloadKey]
	if cache == nil {
		return nil
	}

	syscallNr, err := e.tracer.GetSyscallNr(syscallName)
	if err != nil {
		return err
	}

	// 1. Identify redundant keys in memory
	prefix := fmt.Sprintf("%d:%s", syscallNr, argumentPrefix)
	cache.mu.Lock()
	var toDelete []string
	for key := range cache.Entries {
		if strings.HasPrefix(key, prefix) {
			toDelete = append(toDelete, key)
		}
	}
	// Delete from memory
	for _, key := range toDelete {
		delete(cache.Entries, key)
	}
	cache.mu.Unlock()

	// 2. Update Store
	_ = e.store.CleanupRedundantRules(workloadKey, syscallName, argumentPrefix)

	// 3. Update Kernel maps
	e.resolver.Refresh()
	pods, _ := e.resolver.DiscoverContainers()
	for _, pod := range pods {
		podWorkloadKey := fmt.Sprintf("%s/%s/%s", pod.OwnerKind, pod.Namespace, pod.OwnerName)
		if podWorkloadKey == workloadKey {
			for _, key := range toDelete {
				arg := key[strings.Index(key, ":")+1:]
				_ = e.tracer.DenySyscall(pod.CgroupID, syscallNr, arg)
			}
		}
	}

	log.Printf("[Engine] Cleaned up %d redundant rules for %s:%s in %s", len(toDelete), syscallName, argumentPrefix, workloadKey)
	return nil
}

// ApproveSyscall authorizes a detected syscall and updates the live tracer.
// Implements api.EngineInterface.
func (e *Engine) ApproveSyscall(req api.ApproveRequest) error {
	e.allowlistsMu.Lock()
	defer e.allowlistsMu.Unlock()

	// 1. Get workload info
	workloadInfo := e.workloads.Get(req.WorkloadKey)
	if workloadInfo == nil {
		return fmt.Errorf("workload not found in cache: %s", req.WorkloadKey)
	}

	// 2. Update in-memory cache
	cache := e.allowlists[req.WorkloadKey]
	if cache == nil {
		cache = e.initAllowlistCacheLocked(req.WorkloadKey, workloadInfo)
	}

	syscallNr, err := e.tracer.GetSyscallNr(req.SyscallName)
	if err != nil {
		return fmt.Errorf("failed to get syscall number: %w", err)
	}

	// Normalize prefix rules by stripping trailing "*"
	if req.IsPrefix {
		req.Argument = strings.TrimSuffix(req.Argument, "*")
	}

	allowlistKey := fmt.Sprintf("%d:%s", syscallNr, req.Argument)
	cache.mu.Lock()
	if req.IsPrefix {
		if cache.PrefixEntries == nil {
			cache.PrefixEntries = make(map[string]bool)
		}
		cache.PrefixEntries[allowlistKey] = true
	} else {
		cache.Entries[allowlistKey] = true
	}
	cache.mu.Unlock()

	// 3. Update store (synchronously for manual approval)
	err = e.store.AddToAllowlist(req.WorkloadKey, workloadInfo.TemplateHash, req.SyscallName, req.Argument, req.IsPrefix, cache.TrainingStarted, workloadInfo.TrainingPeriod)
	if err != nil {
		return fmt.Errorf("failed to persist approval to store: %w", err)
	}

	// 4. Cleanup redundant rules if requested
	if req.IsPrefix && req.CleanupMatched {
		_ = e.cleanupRedundantRulesLocked(req.WorkloadKey, req.SyscallName, req.Argument)
	}

	// 5. Update kernel maps for all relevant pods
	count := 0
	e.resolver.Refresh()
	pods, _ := e.resolver.DiscoverContainers()
	for _, pod := range pods {
		podWorkloadKey := fmt.Sprintf("%s/%s/%s", pod.OwnerKind, pod.Namespace, pod.OwnerName)
		if podWorkloadKey == req.WorkloadKey {
			if req.IsPrefix {
				_ = e.tracer.AllowPrefix(pod.CgroupID, syscallNr, req.Argument)
			} else {
				_ = e.tracer.AllowSyscall(pod.CgroupID, syscallNr, req.Argument)
			}
			count++
		}
	}
	log.Printf("[Engine] Manually approved %s:%s for workload %s (updated %d containers, cleanup=%v)", req.SyscallName, req.Argument, req.WorkloadKey, count, req.CleanupMatched)

	// 5. Log audit entry
	_ = e.store.LogPolicyChange(&store.PolicyAuditEntry{
		UserID:      "dashboard-user",
		WorkloadKey: req.WorkloadKey,
		Action:      "ALLOW",
		SyscallName: req.SyscallName,
		Argument:    req.Argument,
		Reason:      "Manual approval from dashboard",
	})

	return nil
}

// RevokeSyscall removes a baseline policy and immediate enforces it in the kernel.
func (e *Engine) RevokeSyscall(req api.ApproveRequest) error {
	e.allowlistsMu.Lock()
	defer e.allowlistsMu.Unlock()

	// 1. Get workload info
	workloadInfo := e.workloads.Get(req.WorkloadKey)
	if workloadInfo == nil {
		return fmt.Errorf("workload not found in cache: %s", req.WorkloadKey)
	}

	// 2. Update in-memory cache
	cache := e.allowlists[req.WorkloadKey]
	if cache == nil {
		return nil // Nothing to revoke
	}

	syscallNr, err := e.tracer.GetSyscallNr(req.SyscallName)
	if err != nil {
		return fmt.Errorf("failed to get syscall number: %w", err)
	}

	// Normalize prefix rules
	if req.IsPrefix {
		req.Argument = strings.TrimSuffix(req.Argument, "*")
	}

	allowlistKey := fmt.Sprintf("%d:%s", syscallNr, req.Argument)
	cache.mu.Lock()
	if req.IsPrefix {
		delete(cache.PrefixEntries, allowlistKey)
	} else {
		delete(cache.Entries, allowlistKey)
	}
	cache.mu.Unlock()

	// 3. Update store
	err = e.store.RevokeFromAllowlist(req.WorkloadKey, req.SyscallName, req.Argument, req.IsPrefix)
	if err != nil {
		return fmt.Errorf("failed to revoke policy from store: %w", err)
	}

	// 4. Update kernel maps for all relevant pods
	count := 0
	e.resolver.Refresh()
	pods, _ := e.resolver.DiscoverContainers()
	for _, pod := range pods {
		podWorkloadKey := fmt.Sprintf("%s/%s/%s", pod.OwnerKind, pod.Namespace, pod.OwnerName)
		if podWorkloadKey == req.WorkloadKey {
			if req.IsPrefix {
				_ = e.tracer.DenyPrefix(pod.CgroupID, syscallNr, req.Argument)
			} else {
				_ = e.tracer.DenySyscall(pod.CgroupID, syscallNr, req.Argument)
			}
			count++
		}
	}
	log.Printf("[Engine] Revoked %s:%s for workload %s (updated %d containers)", req.SyscallName, req.Argument, req.WorkloadKey, count)

	// 5. Log audit entry
	_ = e.store.LogPolicyChange(&store.PolicyAuditEntry{
		UserID:      "dashboard-user",
		WorkloadKey: req.WorkloadKey,
		Action:      "REVOKE",
		SyscallName: req.SyscallName,
		Argument:    req.Argument,
		Reason:      "Manual revocation",
	})

	return nil
}

// ClearBaseline removes all learned policies for a workload.
func (e *Engine) ClearBaseline(workloadKey string) error {
	e.allowlistsMu.Lock()
	defer e.allowlistsMu.Unlock()

	// 1. Get cache for workload
	cache := e.allowlists[workloadKey]
	if cache == nil {
		return nil
	}

	// 2. Discover containers
	e.resolver.Refresh()
	pods, _ := e.resolver.DiscoverContainers()
	var targets []resolver.ContainerInfo
	for _, pod := range pods {
		podWorkloadKey := fmt.Sprintf("%s/%s/%s", pod.OwnerKind, pod.Namespace, pod.OwnerName)
		if podWorkloadKey == workloadKey {
			targets = append(targets, pod)
		}
	}

	// 3. Remove rules from kernel maps for each container
	cache.mu.Lock()
	for _, pod := range targets {
		// Clear standard syscalls
		for key := range cache.Entries {
			var syscallNr int
			fmt.Sscanf(key, "%d:", &syscallNr)
			arg := key[strings.Index(key, ":")+1:]
			_ = e.tracer.DenySyscall(pod.CgroupID, syscallNr, arg)
		}
		// Clear prefix syscalls
		for key := range cache.PrefixEntries {
			var syscallNr int
			fmt.Sscanf(key, "%d:", &syscallNr)
			arg := key[strings.Index(key, ":")+1:]
			_ = e.tracer.DenyPrefix(pod.CgroupID, syscallNr, arg)
		}
	}
	cache.mu.Unlock()

	// 4. Update store
	err := e.store.ClearBaseline(workloadKey)
	if err != nil {
		return fmt.Errorf("failed to clear baseline from store: %w", err)
	}

	// 5. Clear in-memory cache
	delete(e.allowlists, workloadKey)

	log.Printf("[Engine] Cleared entire baseline for workload %s (updated %d containers)", workloadKey, len(targets))

	// 6. Log audit entry
	_ = e.store.LogPolicyChange(&store.PolicyAuditEntry{
		UserID:      "dashboard-user",
		WorkloadKey: workloadKey,
		Action:      "CLEAR_BASELINE",
		Reason:      "Manual clear from dashboard",
	})

	return nil
}

// BulkApproveSyscalls authorizes multiple detected syscalls in one go.
func (e *Engine) BulkApproveSyscalls(req api.BulkApproveRequest) error {
	if len(req.Requests) == 0 {
		return nil
	}

	e.allowlistsMu.Lock()
	defer e.allowlistsMu.Unlock()

	// 1. Refresh pods once for bulk update
	e.resolver.Refresh()
	pods, _ := e.resolver.DiscoverContainers()

	for _, r := range req.Requests {
		// 1. Get workload info
		workloadInfo := e.workloads.Get(r.WorkloadKey)
		if workloadInfo == nil {
			log.Printf("[Engine] Warning: workload not found for bulk approval: %s", r.WorkloadKey)
			continue
		}

		// 2. Update in-memory cache
		cache := e.allowlists[r.WorkloadKey]
		if cache == nil {
			cache = e.initAllowlistCacheLocked(r.WorkloadKey, workloadInfo)
		}

		syscallNr, err := e.tracer.GetSyscallNr(r.SyscallName)
		if err != nil {
			log.Printf("[Engine] Warning: unknown syscall %s for bulk approval", r.SyscallName)
			continue
		}

		allowlistKey := fmt.Sprintf("%d:%s", syscallNr, r.Argument)
		cache.mu.Lock()
		if r.IsPrefix {
			if cache.PrefixEntries == nil {
				cache.PrefixEntries = make(map[string]bool)
			}
			cache.PrefixEntries[allowlistKey] = true
		} else {
			if cache.Entries[allowlistKey] {
				cache.mu.Unlock()
				continue // Already allowed
			}
			cache.Entries[allowlistKey] = true
		}
		cache.mu.Unlock()

		// 3. Update store
		err = e.store.AddToAllowlist(r.WorkloadKey, workloadInfo.TemplateHash, r.SyscallName, r.Argument, r.IsPrefix, cache.TrainingStarted, workloadInfo.TrainingPeriod)
		if err != nil {
			log.Printf("[Engine] Error: failed to persist bulk approval: %v", err)
			continue
		}

		// 4. Update kernel maps
		for _, pod := range pods {
			podWorkloadKey := fmt.Sprintf("%s/%s/%s", pod.OwnerKind, pod.Namespace, pod.OwnerName)
			if podWorkloadKey == r.WorkloadKey {
				if r.IsPrefix {
					_ = e.tracer.AllowPrefix(pod.CgroupID, syscallNr, r.Argument)
				} else {
					_ = e.tracer.AllowSyscall(pod.CgroupID, syscallNr, r.Argument)
				}
			}
		}

		// 5. Log audit entry
		_ = e.store.LogPolicyChange(&store.PolicyAuditEntry{
			UserID:      "dashboard-user",
			WorkloadKey: r.WorkloadKey,
			Action:      "ALLOW",
			SyscallName: r.SyscallName,
			Argument:    r.Argument,
			Reason:      "Bulk manual approval from dashboard",
		})
	}

	log.Printf("[Engine] Processed bulk approval for %d syscalls", len(req.Requests))
	return nil
}

// SetWorkloadMode updates the security mode for a workload.
func (e *Engine) SetWorkloadMode(workloadKey string, mode string) error {
	parts := strings.Split(workloadKey, "/")
	if len(parts) != 3 {
		return fmt.Errorf("invalid workload key: %s", workloadKey)
	}
	kind, namespace, name := parts[0], parts[1], parts[2]

	updates := make(map[string]string)
	switch strings.ToLower(mode) {
	case "learning", "training":
		updates[AnnotationDryRun] = "true"
		updates[AnnotationTrainingPeriod] = "24h"
		updates[AnnotationSecure] = "true"
	case "enforcing", "enforce":
		updates[AnnotationDryRun] = "false"
		updates[AnnotationTrainingPeriod] = "0s"
		updates[AnnotationSecure] = "true"
	case "dryrun":
		updates[AnnotationDryRun] = "true"
	case "active":
		updates[AnnotationDryRun] = "false"
	case "monitor":
		updates[AnnotationSecure] = "true"
		updates[AnnotationDryRun] = "true" // Default to dry-run when starting monitoring
	case "unmonitor":
		updates[AnnotationSecure] = "false"
	default:
		return fmt.Errorf("invalid mode: %s", mode)
	}

	return e.workloads.UpdateWorkloadAnnotations(e.ctx, kind, namespace, name, updates)
}

// GetPolicyAudit returns the manual change history for a workload.
func (e *Engine) GetPolicyAudit(workloadKey string) ([]store.PolicyAuditEntry, error) {
	return e.store.GetPolicyAudit(workloadKey)
}

// GetGlobalAudit returns the manual change history across all workloads.
func (e *Engine) GetGlobalAudit(limit int) ([]store.PolicyAuditEntry, error) {
	return e.store.GetGlobalAudit(limit)
}

// GetWorkloadBaseline returns the current allowlist entries for a workload.
func (e *Engine) GetWorkloadBaseline(workloadKey string) ([]store.AllowlistEntry, error) {
	return e.store.GetWorkloadBaseline(workloadKey)
}

// Authenticate verifies a Kubernetes token and returns user info.
func (e *Engine) Authenticate(token string) (bool, string, error) {
	status, err := e.resolver.AuthenticateToken(token)
	if err != nil {
		return false, "", err
	}

	if status.Authenticated {
		return true, status.User.Username, nil
	}

	return false, "", nil
}
