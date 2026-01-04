// Package engine provides workload configuration caching.
package engine

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// AnnotationSecure enables security enforcement
	AnnotationSecure = "icu.systems/secure"
	// AnnotationTrainingPeriod defines the training duration
	AnnotationTrainingPeriod = "icu.systems/training-period"
	// AnnotationDryRun enables log-only enforcement
	AnnotationDryRun = "icu.systems/dry-run"
	// DefaultTrainingPeriod is 24 hours
	DefaultTrainingPeriod = 24 * time.Hour
)

// WorkloadInfo holds security configuration for a workload.
type WorkloadInfo struct {
	Kind           string
	Namespace      string
	Name           string
	Secure         bool
	TrainingPeriod time.Duration
	ExplicitPeriod bool
	DryRun         bool
	TemplateHash   string // pod-template-hash for change detection
}

// WorkloadCache caches workload security configurations from K8s.
type WorkloadCache struct {
	client      kubernetes.Interface
	clusterName string
	workloads   map[string]*WorkloadInfo // "Kind/Namespace/Name" -> info
	mu          sync.RWMutex

	onChange func(workloadKey string, info *WorkloadInfo)
}

// NewWorkloadCache creates a new workload cache.
func NewWorkloadCache() (*WorkloadCache, error) {
	client, clusterName, err := getK8sClient()
	if err != nil {
		return nil, err
	}

	return &WorkloadCache{
		client:      client,
		clusterName: clusterName,
		workloads:   make(map[string]*WorkloadInfo),
	}, nil
}

// OnChange sets a callback for workload configuration changes.
func (c *WorkloadCache) OnChange(fn func(workloadKey string, info *WorkloadInfo)) {
	c.onChange = fn
}

// Get returns the workload info for a given key.
func (c *WorkloadCache) Get(workloadKey string) *WorkloadInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.workloads[workloadKey]
}

// Start begins watching K8s workloads.
func (c *WorkloadCache) Start(ctx context.Context) error {
	factory := informers.NewSharedInformerFactory(c.client, 5*time.Minute)

	// Watch Deployments
	deployInformer := factory.Apps().V1().Deployments().Informer()
	deployInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.handleDeployment(obj.(*appsv1.Deployment)) },
		UpdateFunc: func(_, obj interface{}) { c.handleDeployment(obj.(*appsv1.Deployment)) },
		DeleteFunc: func(obj interface{}) {
			c.removeWorkload("Deployment", obj.(*appsv1.Deployment).Namespace, obj.(*appsv1.Deployment).Name)
		},
	})

	// Watch StatefulSets
	stsInformer := factory.Apps().V1().StatefulSets().Informer()
	stsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.handleStatefulSet(obj.(*appsv1.StatefulSet)) },
		UpdateFunc: func(_, obj interface{}) { c.handleStatefulSet(obj.(*appsv1.StatefulSet)) },
		DeleteFunc: func(obj interface{}) {
			c.removeWorkload("StatefulSet", obj.(*appsv1.StatefulSet).Namespace, obj.(*appsv1.StatefulSet).Name)
		},
	})

	// Watch DaemonSets
	dsInformer := factory.Apps().V1().DaemonSets().Informer()
	dsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.handleDaemonSet(obj.(*appsv1.DaemonSet)) },
		UpdateFunc: func(_, obj interface{}) { c.handleDaemonSet(obj.(*appsv1.DaemonSet)) },
		DeleteFunc: func(obj interface{}) {
			c.removeWorkload("DaemonSet", obj.(*appsv1.DaemonSet).Namespace, obj.(*appsv1.DaemonSet).Name)
		},
	})

	// Watch Jobs
	jobInformer := factory.Batch().V1().Jobs().Informer()
	jobInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.handleJob(obj.(*batchv1.Job)) },
		UpdateFunc: func(_, obj interface{}) { c.handleJob(obj.(*batchv1.Job)) },
		DeleteFunc: func(obj interface{}) { c.removeWorkload("Job", obj.(*batchv1.Job).Namespace, obj.(*batchv1.Job).Name) },
	})

	// Start informers
	factory.Start(ctx.Done())

	// Wait for cache sync
	log.Println("[WorkloadCache] Syncing K8s informers...")
	if !cache.WaitForCacheSync(ctx.Done(),
		deployInformer.HasSynced,
		stsInformer.HasSynced,
		dsInformer.HasSynced,
		jobInformer.HasSynced,
	) {
		return fmt.Errorf("failed to sync informer caches")
	}
	log.Println("[WorkloadCache] K8s informers synced")

	return nil
}

func (c *WorkloadCache) handleDeployment(deploy *appsv1.Deployment) {
	// Versioning removed: policies now persist across all versions.
	templateHash := "v1"
	info := parseWorkloadInfo("Deployment", deploy.Namespace, deploy.Name, deploy.Annotations, templateHash)
	c.updateWorkload(info)
}

func (c *WorkloadCache) handleStatefulSet(sts *appsv1.StatefulSet) {
	// Versioning removed: policies now persist across all versions.
	templateHash := "v1"
	info := parseWorkloadInfo("StatefulSet", sts.Namespace, sts.Name, sts.Annotations, templateHash)
	c.updateWorkload(info)
}

func (c *WorkloadCache) handleDaemonSet(ds *appsv1.DaemonSet) {
	// Versioning removed: policies now persist across all versions.
	templateHash := "v1"
	info := parseWorkloadInfo("DaemonSet", ds.Namespace, ds.Name, ds.Annotations, templateHash)
	c.updateWorkload(info)
}

func (c *WorkloadCache) handleJob(job *batchv1.Job) {
	// Versioning removed: policies now persist across all versions.
	templateHash := "v1"
	info := parseWorkloadInfo("Job", job.Namespace, job.Name, job.Annotations, templateHash)
	c.updateWorkload(info)
}

func parseWorkloadInfo(kind, namespace, name string, annotations map[string]string, templateHash string) *WorkloadInfo {
	info := &WorkloadInfo{
		Kind:           kind,
		Namespace:      namespace,
		Name:           name,
		Secure:         false,
		TrainingPeriod: DefaultTrainingPeriod,
	}

	if annotations != nil {
		// Parse icu.systems/secure
		if v, ok := annotations[AnnotationSecure]; ok {
			info.Secure = strings.ToLower(v) == "true"
		}

		// Parse icu.systems/training-period
		if v, ok := annotations[AnnotationTrainingPeriod]; ok {
			if d, err := parseDuration(v); err == nil {
				info.TrainingPeriod = d
				info.ExplicitPeriod = true
			}
		}

		// Parse icu.systems/dry-run
		if v, ok := annotations[AnnotationDryRun]; ok {
			info.DryRun = strings.ToLower(v) == "true"
		}
	}

	// Set template hash for change detection
	info.TemplateHash = templateHash

	return info
}

func (c *WorkloadCache) updateWorkload(info *WorkloadInfo) {
	key := fmt.Sprintf("%s/%s/%s", info.Kind, info.Namespace, info.Name)

	c.mu.Lock()
	oldInfo := c.workloads[key]
	c.workloads[key] = info
	c.mu.Unlock()

	// Notify of change
	if c.onChange != nil {
		// Check if this is a meaningful change
		if oldInfo == nil || oldInfo.Secure != info.Secure || oldInfo.TemplateHash != info.TemplateHash ||
			oldInfo.DryRun != info.DryRun || oldInfo.TrainingPeriod != info.TrainingPeriod ||
			oldInfo.ExplicitPeriod != info.ExplicitPeriod {
			c.onChange(key, info)
		}
	}
}

func (c *WorkloadCache) removeWorkload(kind, namespace, name string) {
	key := fmt.Sprintf("%s/%s/%s", kind, namespace, name)

	c.mu.Lock()
	delete(c.workloads, key)
	c.mu.Unlock()
}

// parseDuration parses duration with support for days (e.g., "7d")
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))

	// Handle days
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil {
			return time.Duration(days) * 24 * time.Hour, nil
		}
	}

	return time.ParseDuration(s)
}

func getK8sClient() (*kubernetes.Clientset, string, error) {
	clusterName := "k8s-cluster"

	// Try in-cluster config first
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
		}

		// To get cluster name, we need to load the config file
		rawConfig, err := clientcmd.LoadFromFile(kubeconfig)
		if err == nil {
			if ctx, ok := rawConfig.Contexts[rawConfig.CurrentContext]; ok {
				clusterName = ctx.Cluster
			}
		}

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get k8s config: %w", err)
		}
	} else {
		// In-cluster: could try to get it from a configmap if we really wanted to.
		// For now, "k8s-cluster" is a safe default.
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, "", err
	}

	return clientset, clusterName, nil
}

// GetClusterName returns the cluster name.
func (c *WorkloadCache) GetClusterName() string {
	return c.clusterName
}

// GetAllSecured returns all secured workload keys.
func (c *WorkloadCache) GetAllSecured() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var keys []string
	for key, info := range c.workloads {
		if info.Secure {
			keys = append(keys, key)
		}
	}
	return keys
}

// Lookup returns workload info by namespace and owner name (for pod resolution).
func (c *WorkloadCache) Lookup(namespace, ownerKind, ownerName string) *WorkloadInfo {
	key := fmt.Sprintf("%s/%s/%s", ownerKind, namespace, ownerName)
	return c.Get(key)
}

// UpdateWorkloadAnnotations updates security annotations on a K8s resource.
func (c *WorkloadCache) UpdateWorkloadAnnotations(ctx context.Context, kind, namespace, name string, updates map[string]string) error {
	switch kind {
	case "Deployment":
		deploy, err := c.client.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if deploy.Annotations == nil {
			deploy.Annotations = make(map[string]string)
		}
		for k, v := range updates {
			deploy.Annotations[k] = v
		}
		_, err = c.client.AppsV1().Deployments(namespace).Update(ctx, deploy, metav1.UpdateOptions{})
		return err

	case "StatefulSet":
		sts, err := c.client.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if sts.Annotations == nil {
			sts.Annotations = make(map[string]string)
		}
		for k, v := range updates {
			sts.Annotations[k] = v
		}
		_, err = c.client.AppsV1().StatefulSets(namespace).Update(ctx, sts, metav1.UpdateOptions{})
		return err

	case "DaemonSet":
		ds, err := c.client.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if ds.Annotations == nil {
			ds.Annotations = make(map[string]string)
		}
		for k, v := range updates {
			ds.Annotations[k] = v
		}
		_, err = c.client.AppsV1().DaemonSets(namespace).Update(ctx, ds, metav1.UpdateOptions{})
		return err

	case "Job":
		job, err := c.client.BatchV1().Jobs(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if job.Annotations == nil {
			job.Annotations = make(map[string]string)
		}
		for k, v := range updates {
			job.Annotations[k] = v
		}
		_, err = c.client.BatchV1().Jobs(namespace).Update(ctx, job, metav1.UpdateOptions{})
		return err

	default:
		return fmt.Errorf("unsupported workload kind: %s", kind)
	}
}
