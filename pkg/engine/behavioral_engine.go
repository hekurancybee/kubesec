package engine

import (
	"log"
	"strings"
	"sync"
)

// BehavioralEngine manages pattern discovery and event deduplication.
type BehavioralEngine struct {
	// Deduplication cache to prevent event explosion in ClickHouse.
	// workload -> syscall -> argument -> count
	recentSeen map[string]map[string]map[string]int
	mu         sync.Mutex

	// Threshold for generalizing a path (e.g. 50 files in same dir -> prefix rule)
	GeneralizationThreshold int
}

// NewBehavioralEngine creates a new behavioral engine.
func NewBehavioralEngine() *BehavioralEngine {
	return &BehavioralEngine{
		recentSeen:              make(map[string]map[string]map[string]int),
		GeneralizationThreshold: 50,
	}
}

// ProcessEvent analyzes a syscall event and returns whether it should be persisted and if it's a prefix.
func (be *BehavioralEngine) ProcessEvent(workloadKey, syscallName, argument string) (persist bool, isPrefix bool, generalizedArg string) {
	be.mu.Lock()
	defer be.mu.Unlock()

	// 1. Initialize workload maps if needed
	if _, ok := be.recentSeen[workloadKey]; !ok {
		be.recentSeen[workloadKey] = make(map[string]map[string]int)
	}
	if _, ok := be.recentSeen[workloadKey][syscallName]; !ok {
		be.recentSeen[workloadKey][syscallName] = make(map[string]int)
	}

	// 2. Increment count for this specific argument
	be.recentSeen[workloadKey][syscallName][argument]++
	count := be.recentSeen[workloadKey][syscallName][argument]

	// 3. Simple Deduplication: only persist new unique arguments once
	if count > 1 {
		return false, false, ""
	}

	// 4. Pattern Discovery: if we see many different files in the same directory, propose a prefix
	// This is a simplified heuristic: if the argument looks like a path, try to generalize it.
	if strings.HasPrefix(argument, "/") {
		lastSlash := strings.LastIndex(argument, "/")
		if lastSlash > 0 {
			parentDir := argument[:lastSlash+1]

			// Count how many unique files we've seen in this parent directory
			dirCount := 0
			for seenArg := range be.recentSeen[workloadKey][syscallName] {
				if strings.HasPrefix(seenArg, parentDir) {
					dirCount++
				}
			}

			if dirCount >= be.GeneralizationThreshold {
				log.Printf("[BehavioralEngine] High cardinality detected in %s for %s (%s). Generalizing to %s*",
					workloadKey, syscallName, parentDir, parentDir)
				return true, true, parentDir // Return parent directory as a prefix rule
			}
		}
	}

	return true, false, argument
}
