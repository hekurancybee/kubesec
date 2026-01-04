// Package resolver provides Kubernetes pod resolution.
package resolver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kubesec/kubesec/pkg/ebpf"
)

// PodInfo contains metadata about a Kubernetes pod.
type PodInfo struct {
	Namespace   string
	PodName     string
	Container   string
	ContainerID string
	OwnerKind   string // Deployment, StatefulSet, DaemonSet, Job
	OwnerName   string
	CgroupID    uint64
}

// K8sResolver resolves container IDs to Kubernetes pod information.
type K8sResolver struct {
	client    *kubernetes.Clientset
	cache     map[string]*PodInfo // containerID -> PodInfo
	cgroupMap map[uint64]*PodInfo // cgroupID -> PodInfo
	mu        sync.RWMutex
}

// GetClient returns the Kubernetes client.
func (r *K8sResolver) GetClient() kubernetes.Interface {
	return r.client
}

// NewK8sResolver creates a new Kubernetes resolver.
func NewK8sResolver() (*K8sResolver, error) {
	config, err := getK8sConfig()
	if err != nil {
		return nil, fmt.Errorf("getting k8s config: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating k8s client: %w", err)
	}

	r := &K8sResolver{
		client:    client,
		cache:     make(map[string]*PodInfo),
		cgroupMap: make(map[uint64]*PodInfo),
	}

	// Initial sync
	if err := r.syncPods(); err != nil {
		return nil, fmt.Errorf("initial pod sync: %w", err)
	}

	return r, nil
}

func getK8sConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
	}

	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

func (r *K8sResolver) syncPods() error {
	pods, err := r.client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing pods: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range pods.Items {
		r.addPodToCache(&pods.Items[i])
	}

	return nil
}

func (r *K8sResolver) addPodToCache(pod *corev1.Pod) {
	ownerKind, ownerName := getOwner(r.client, pod)

	for _, status := range pod.Status.ContainerStatuses {
		containerID := extractContainerID(status.ContainerID)
		if containerID == "" {
			continue
		}

		info := &PodInfo{
			Namespace:   pod.Namespace,
			PodName:     pod.Name,
			Container:   status.Name,
			ContainerID: containerID,
			OwnerKind:   ownerKind,
			OwnerName:   ownerName,
		}
		r.cache[containerID] = info
	}

	for _, status := range pod.Status.InitContainerStatuses {
		containerID := extractContainerID(status.ContainerID)
		if containerID == "" {
			continue
		}

		info := &PodInfo{
			Namespace:   pod.Namespace,
			PodName:     pod.Name,
			Container:   status.Name,
			ContainerID: containerID,
			OwnerKind:   ownerKind,
			OwnerName:   ownerName,
		}
		r.cache[containerID] = info
	}
}

func getOwner(client *kubernetes.Clientset, pod *corev1.Pod) (kind, name string) {
	for _, owner := range pod.OwnerReferences {
		switch owner.Kind {
		case "ReplicaSet":
			// ReplicaSet names are: deployment-name-hash
			// Try to get the Deployment
			rs, err := client.AppsV1().ReplicaSets(pod.Namespace).Get(context.Background(), owner.Name, metav1.GetOptions{})
			if err == nil {
				for _, rsOwner := range rs.OwnerReferences {
					if rsOwner.Kind == "Deployment" {
						return "Deployment", rsOwner.Name
					}
				}
			}
			// Fallback: strip hash from ReplicaSet name
			parts := strings.Split(owner.Name, "-")
			if len(parts) > 1 {
				return "Deployment", strings.Join(parts[:len(parts)-1], "-")
			}
			return "ReplicaSet", owner.Name
		case "StatefulSet", "DaemonSet", "Job":
			return owner.Kind, owner.Name
		}
	}
	// No owner, use pod itself
	return "Pod", pod.Name
}

func extractContainerID(fullID string) string {
	if fullID == "" {
		return ""
	}
	parts := strings.SplitN(fullID, "://", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return fullID
}

// ResolveContainerID resolves a container ID to pod info.
func (r *K8sResolver) ResolveContainerID(containerID string) *PodInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if info, ok := r.cache[containerID]; ok {
		return info
	}

	// Try prefix match
	for id, info := range r.cache {
		if strings.HasPrefix(id, containerID) || strings.HasPrefix(containerID, id) {
			return info
		}
	}

	return nil
}

// RegisterCgroupID maps a cgroup ID to a container ID.
func (r *K8sResolver) RegisterCgroupID(cgroupID uint64, containerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if info, ok := r.cache[containerID]; ok {
		infoCopy := *info
		infoCopy.CgroupID = cgroupID
		r.cgroupMap[cgroupID] = &infoCopy
	}
}

// ResolveCgroupID resolves a cgroup ID to pod info.
func (r *K8sResolver) ResolveCgroupID(cgroupID uint64) *PodInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cgroupMap[cgroupID]
}

// ResolvePID resolves a PID to pod info.
func (r *K8sResolver) ResolvePID(pid uint32) *PodInfo {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return nil
	}

	containerID := extractContainerIDFromCgroup(string(data))
	if containerID == "" {
		return nil
	}

	return r.ResolveContainerID(containerID)
}

func extractContainerIDFromCgroup(cgroupData string) string {
	patterns := []string{
		"cri-containerd-",
		"docker-",
		"crio-",
	}

	for _, pattern := range patterns {
		idx := strings.Index(cgroupData, pattern)
		if idx == -1 {
			continue
		}

		remaining := cgroupData[idx+len(pattern):]
		remaining = strings.TrimSuffix(remaining, ".scope")

		// Find end of container ID
		if newlineIdx := strings.Index(remaining, "\n"); newlineIdx != -1 {
			remaining = remaining[:newlineIdx]
		}

		remaining = strings.TrimSpace(remaining)
		if len(remaining) >= 12 {
			return remaining
		}
	}

	return ""
}

// ContainerInfo holds discovered container info.
type ContainerInfo struct {
	Namespace   string
	PodName     string
	Container   string
	ContainerID string
	OwnerKind   string
	OwnerName   string
	CgroupID    uint64
}

// DiscoverContainers finds all K8s containers and their cgroup IDs.
func (r *K8sResolver) DiscoverContainers() ([]ContainerInfo, error) {
	// Refresh pod cache first
	if err := r.syncPods(); err != nil {
		return nil, err
	}

	var containers []ContainerInfo

	// Walk cgroup paths to find containers
	paths := []string{
		"/sys/fs/cgroup/kubepods.slice",
		"/sys/fs/cgroup/kubepods",
	}

	// Also check docker-based K8s (minikube)
	systemSlice := "/sys/fs/cgroup/system.slice"
	entries, err := os.ReadDir(systemSlice)
	if err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "docker-") && strings.HasSuffix(entry.Name(), ".scope") {
				kubepodPath := filepath.Join(systemSlice, entry.Name(), "kubepods.slice")
				if _, err := os.Stat(kubepodPath); err == nil {
					paths = append(paths, kubepodPath)
				}
			}
		}
	}

	for _, basePath := range paths {
		if _, err := os.Stat(basePath); err != nil {
			continue
		}
		r.walkCgroup(basePath, &containers)
	}

	return containers, nil
}

func (r *K8sResolver) walkCgroup(basePath string, containers *[]ContainerInfo) {
	filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}

		name := filepath.Base(path)
		isContainer := strings.Contains(name, "cri-containerd-") ||
			strings.Contains(name, "docker-") ||
			strings.Contains(name, "crio-") ||
			(strings.Contains(path, "kubepods") && strings.HasSuffix(name, ".scope"))

		if !isContainer {
			return nil
		}

		// Read cgroup.procs to get a PID
		procsPath := filepath.Join(path, "cgroup.procs")
		data, err := os.ReadFile(procsPath)
		if err != nil {
			return nil
		}

		procs := strings.TrimSpace(string(data))
		if procs == "" {
			return nil
		}

		pids := strings.Split(procs, "\n")
		if len(pids) == 0 {
			return nil
		}

		pid, _ := strconv.Atoi(pids[0])
		if pid == 0 {
			return nil
		}

		cgroupID, err := ebpf.GetCgroupIDForPID(pid)
		if err != nil {
			return nil
		}

		// Extract container ID and resolve
		containerID := extractFullContainerID(name)
		podInfo := r.ResolveContainerID(containerID)

		if podInfo != nil {
			// Register cgroup mapping
			r.RegisterCgroupID(cgroupID, containerID)

			*containers = append(*containers, ContainerInfo{
				Namespace:   podInfo.Namespace,
				PodName:     podInfo.PodName,
				Container:   podInfo.Container,
				ContainerID: containerID,
				OwnerKind:   podInfo.OwnerKind,
				OwnerName:   podInfo.OwnerName,
				CgroupID:    cgroupID,
			})
		}

		return nil
	})
}

func extractFullContainerID(cgroupName string) string {
	name := strings.TrimSuffix(cgroupName, ".scope")

	switch {
	case strings.HasPrefix(name, "cri-containerd-"):
		return strings.TrimPrefix(name, "cri-containerd-")
	case strings.HasPrefix(name, "docker-"):
		return strings.TrimPrefix(name, "docker-")
	case strings.HasPrefix(name, "crio-"):
		return strings.TrimPrefix(name, "crio-")
	default:
		return ""
	}
}

// Refresh re-syncs the pod cache.
func (r *K8sResolver) Refresh() error {
	return r.syncPods()
}

// GetNodeCount returns the total number of nodes in the cluster.
func (r *K8sResolver) GetNodeCount() int {
	nodes, err := r.client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return 0
	}
	return len(nodes.Items)
}

// GetNamespaceCount returns the total number of namespaces in the cluster.
func (r *K8sResolver) GetNamespaceCount() int {
	namespaces, err := r.client.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return 0
	}
	return len(namespaces.Items)
}

// AuthenticateToken verifies a Kubernetes token using the TokenReview API.
func (r *K8sResolver) AuthenticateToken(token string) (*authenticationv1.TokenReviewStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	review := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}

	result, err := r.client.AuthenticationV1().TokenReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return &result.Status, nil
}
