package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/kubesec/kubesec/pkg/store"
)

// EngineInterface defines the methods the API needs from the core engine.
// This decodes the circular dependency if we were to import pkg/engine.
type EngineInterface interface {
	GetWorkloads() []WorkloadStatus
	GetStatsSummary(windowMinutes int) (StatsSummary, error)
	GetTimeseries(windowMinutes int) ([]TimeseriesPoint, error)
	GetTopNamespaces(windowMinutes int) ([]NamespaceStats, error)
	GetDetections(limit int, offset int, windowMinutes int, search string, grouped bool) ([]Detection, error)
	CountDetections(windowMinutes int, search string, grouped bool) (int64, error)
	GetLearningQueue(limit int) ([]Detection, error)
	ApproveSyscall(req ApproveRequest) error
	BulkApproveSyscalls(req BulkApproveRequest) error
	RevokeSyscall(req ApproveRequest) error
	ClearBaseline(workloadKey string) error
	GetPolicyAudit(workloadKey string) ([]store.PolicyAuditEntry, error)
	GetGlobalAudit(limit int) ([]store.PolicyAuditEntry, error)
	GetWorkloadBaseline(workloadKey string) ([]store.AllowlistEntry, error)
	// SetWorkloadMode updates the security mode for a workload.
	SetWorkloadMode(workloadKey string, mode string) error
	// Authenticate verifies a Kubernetes token.
	Authenticate(token string) (bool, string, error)
}

// WorkloadStatus represents the current state of a Kubernetes workload.
type WorkloadStatus struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Namespace        string    `json:"namespace"`
	Kind             string    `json:"kind"`
	Status           string    `json:"status"` // "learning", "observing", "enforcing", "unmonitored"
	TrainingProgress int       `json:"trainingProgress"`
	TemplateHash     string    `json:"templateHash"`
	Secure           bool      `json:"secure"`
	DryRun           bool      `json:"dryRun"`
	LastSync         time.Time `json:"lastSync"`
	Replicas         int       `json:"replicas"`
	PolicyVersion    string    `json:"policyVersion"`
}

// StatsSummary represents high-level metrics.
type StatsSummary struct {
	ClusterName    string `json:"clusterName"`
	TotalEvents    uint64 `json:"totalEvents"`
	BlockedEvents  uint64 `json:"blockedEvents"`
	ObservedEvents uint64 `json:"observedEvents"`
	LearnedEvents  uint64 `json:"learnedEvents"`
	NodeCount      int    `json:"nodeCount"`
	NamespaceCount int    `json:"namespaceCount"`
}

// TimeseriesPoint represents a single data point in a chart.
type TimeseriesPoint struct {
	Timestamp time.Time `json:"t"`
	Allowed   uint64    `json:"allowed"`
	Learned   uint64    `json:"learned"`
	Blocked   uint64    `json:"blocked"`
	Observed  uint64    `json:"observed"`
}

// NamespaceStats represents blocked counts per namespace.
type NamespaceStats struct {
	Namespace     string `json:"namespace"`
	BlockedCount  uint64 `json:"blockedCount"`
	ObservedCount uint64 `json:"observedCount"`
}

// ApproveRequest represents a request to authorize a syscall.
type ApproveRequest struct {
	WorkloadKey    string `json:"workloadKey"`
	SyscallName    string `json:"syscallName"`
	Argument       string `json:"argument"`
	IsPrefix       bool   `json:"isPrefix"`
	CleanupMatched bool   `json:"cleanupMatched"` // NEW: delete redundant entries covered by this pattern
}

type BulkApproveRequest struct {
	Requests []ApproveRequest `json:"requests"`
}

type SetModeRequest struct {
	WorkloadKey string `json:"workloadKey"`
	Mode        string `json:"mode"` // "learning" or "enforcing"
}

// Detection represents a security event/alert for the dashboard.
type Detection struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Namespace   string    `json:"namespace"`
	PodName     string    `json:"podName"`
	WorkloadKey string    `json:"workloadKey"`
	SyscallName string    `json:"syscallName"`
	Argument    string    `json:"argument"`
	Comm        string    `json:"comm"`
	Action      string    `json:"action"`   // "blocked", "observed"
	Risk        string    `json:"risk"`     // "high", "medium", "low"
	IsPrefix    bool      `json:"isPrefix"` // For behavioral patterns
	Count       int64     `json:"count"`
	LastSeen    time.Time `json:"lastSeen"`
}

// Server handles dashboard API requests.
type Server struct {
	engine EngineInterface
	router *gin.Engine
	srv    *http.Server
}

// NewServer creates a new API server.
func NewServer(engine EngineInterface) *Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Setup CORS
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	s := &Server{
		engine: engine,
		router: router,
	}

	s.setupRoutes()

	return s
}

func (s *Server) setupRoutes() {
	api := s.router.Group("/api")
	{
		api.POST("/auth/login", s.handleLogin)
		api.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		// Protected routes
		protected := api.Group("/")
		protected.Use(s.AuthMiddleware())
		{
			protected.GET("/workloads", s.handleListWorkloads)
			protected.GET("/stats/summary", s.handleGetStatsSummary)
			protected.GET("/stats/timeseries", s.handleGetTimeseries)
			protected.GET("/stats/top-namespaces", s.handleGetTopNamespaces)
			protected.GET("/detections", s.handleGetDetections)
			protected.GET("/policies/baseline", s.handleGetLearningQueue)

			// Policy Management
			protected.POST("/policies/approve", s.handleApproveSyscall)
			protected.POST("/policies/bulk-approve", s.handleBulkApproveSyscalls)
			protected.POST("/workloads/mode", s.handleSetWorkloadMode)
			protected.DELETE("/policies/revoke", s.handleRevokeSyscall)
			protected.DELETE("/policies/baseline/all", s.handleClearBaseline)
			protected.GET("/policies/audit", s.handleGetPolicyAudit)
			protected.GET("/audit/global", s.handleGetGlobalAudit)
			protected.GET("/policies/baseline/export", s.handleGetWorkloadBaseline)
		}
	}
}

func (s *Server) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		token := authHeader[7:]
		ok, username, err := s.engine.Authenticate(token)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("username", username)
		c.Next()
	}
}

func (s *Server) handleLogin(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ok, username, err := s.engine.Authenticate(req.Token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"username":      username,
	})
}

// Start runs the API server.
func (s *Server) Start(port int) error {
	s.srv = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: s.router,
	}

	log.Printf("[API] Dashboard API listening on %s", s.srv.Addr)

	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[API] Error: %v", err)
		}
	}()

	return nil
}

// Stop shut downs the API server.
func (s *Server) Stop() error {
	if s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

func (s *Server) handleListWorkloads(c *gin.Context) {
	workloads := s.engine.GetWorkloads()
	c.JSON(http.StatusOK, workloads)
}

func (s *Server) handleGetStatsSummary(c *gin.Context) {
	window := 1440 // Default 24h
	if w := c.Query("window"); w != "" {
		fmt.Sscanf(w, "%d", &window)
	}
	stats, err := s.engine.GetStatsSummary(window)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}

func (s *Server) handleGetTimeseries(c *gin.Context) {
	window := 1440 // Default 24h
	if w := c.Query("window"); w != "" {
		fmt.Sscanf(w, "%d", &window)
	}
	points, err := s.engine.GetTimeseries(window)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, points)
}

func (s *Server) handleGetTopNamespaces(c *gin.Context) {
	window := 1440 // Default 24h
	if w := c.Query("window"); w != "" {
		fmt.Sscanf(w, "%d", &window)
	}
	stats, err := s.engine.GetTopNamespaces(window)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// handleGetDetections returns recent security alerts.
func (s *Server) handleGetDetections(c *gin.Context) {
	limit := 100
	if l := c.Query("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}

	page := 1
	if p := c.Query("page"); p != "" {
		if val, err := strconv.Atoi(p); err == nil && val > 0 {
			page = val
		}
	}
	offset := (page - 1) * limit

	windowMinutes := 15
	if w := c.Query("window"); w != "" {
		if val, err := strconv.Atoi(w); err == nil && val > 0 {
			windowMinutes = val
		}
	}

	search := c.Query("search")
	grouped := c.Query("grouped") == "true"

	detections, err := s.engine.GetDetections(limit, offset, windowMinutes, search, grouped)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	total, err := s.engine.CountDetections(windowMinutes, search, grouped)
	if err != nil {
		// Log error but continue with count of 0 or partial data?
		// For now just allow it to fail silently on count or return what we have?
		// Let's assume strictness for now but maybe we should return detections anyway.
	}

	c.JSON(http.StatusOK, gin.H{
		"data": detections,
		"meta": gin.H{
			"total": total,
			"page":  page,
			"limit": limit,
		},
	})
}

func (s *Server) handleGetLearningQueue(c *gin.Context) {
	items, err := s.engine.GetLearningQueue(100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, items)
}

func (s *Server) handleApproveSyscall(c *gin.Context) {
	var req ApproveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.engine.ApproveSyscall(req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "approved"})
}

func (s *Server) handleBulkApproveSyscalls(c *gin.Context) {
	var req BulkApproveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.engine.BulkApproveSyscalls(req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "bulk_approved", "count": len(req.Requests)})
}

func (s *Server) handleSetWorkloadMode(c *gin.Context) {
	var req SetModeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.engine.SetWorkloadMode(req.WorkloadKey, req.Mode); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "mode_updated"})
}

func (s *Server) handleRevokeSyscall(c *gin.Context) {
	var req ApproveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.engine.RevokeSyscall(req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleClearBaseline(c *gin.Context) {
	workloadKey := c.Query("workloadKey")
	if workloadKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workloadKey is required"})
		return
	}

	if err := s.engine.ClearBaseline(workloadKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleGetPolicyAudit(c *gin.Context) {
	workloadKey := c.Query("workloadKey")
	if workloadKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workloadKey is required"})
		return
	}

	audit, err := s.engine.GetPolicyAudit(workloadKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, audit)
}

func (s *Server) handleGetGlobalAudit(c *gin.Context) {
	limitStr := c.Query("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	entries, err := s.engine.GetGlobalAudit(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, entries)
}

func (s *Server) handleGetWorkloadBaseline(c *gin.Context) {
	workloadKey := c.Query("workloadKey")
	if workloadKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workloadKey is required"})
		return
	}

	baseline, err := s.engine.GetWorkloadBaseline(workloadKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, baseline)
}
