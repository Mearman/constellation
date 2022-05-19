package k8sapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/edgelesssys/constellation/coordinator/kubernetes/k8sapi/resources"
	kubeadm "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm/v1beta3"
)

const (
	// kubeConfig is the path to the Kubernetes admin config (used for authentication).
	kubeConfig = "/etc/kubernetes/admin.conf"
	// kubeletStartTimeout is the maximum time given to the kubelet service to (re)start.
	kubeletStartTimeout = 10 * time.Minute
)

// Client provides the functionality of `kubectl apply`.
type Client interface {
	Apply(resources resources.Marshaler, forceConflicts bool) error
	SetKubeconfig(kubeconfig []byte)
	// TODO: add tolerations
}

type ClusterUtil interface {
	InstallComponents(ctx context.Context, version string) error
	InitCluster(initConfig []byte) error
	JoinCluster(joinConfig []byte) error
	SetupPodNetwork(kubectl Client, podNetworkConfiguration resources.Marshaler) error
	SetupAutoscaling(kubectl Client, clusterAutoscalerConfiguration resources.Marshaler, secrets resources.Marshaler) error
	SetupCloudControllerManager(kubectl Client, cloudControllerManagerConfiguration resources.Marshaler, configMaps resources.Marshaler, secrets resources.Marshaler) error
	SetupCloudNodeManager(kubectl Client, cloudNodeManagerConfiguration resources.Marshaler) error
	StartKubelet() error
	RestartKubelet() error
	GetControlPlaneJoinCertificateKey() (string, error)
	CreateJoinToken(ttl time.Duration) (*kubeadm.BootstrapTokenDiscovery, error)
}

// KubernetesUtil provides low level management of the kubernetes cluster.
type KubernetesUtil struct {
	inst installer
}

// NewKubernetesUtils creates a new KubernetesUtil.
func NewKubernetesUtil() *KubernetesUtil {
	return &KubernetesUtil{
		inst: newOSInstaller(),
	}
}

// InstallComponents installs kubernetes components in the version specified.
func (k *KubernetesUtil) InstallComponents(ctx context.Context, version string) error {
	var versionConf kubernetesVersion
	var ok bool
	if versionConf, ok = versionConfigs[version]; !ok {
		return fmt.Errorf("unsupported kubernetes version %q", version)
	}
	if err := versionConf.installK8sComponents(ctx, k.inst); err != nil {
		return err
	}

	return enableSystemdUnit(ctx, kubeletServiceEtcPath)
}

func (k *KubernetesUtil) InitCluster(initConfig []byte) error {
	// TODO: audit policy should be user input
	auditPolicy, err := resources.NewDefaultAuditPolicy().Marshal()
	if err != nil {
		return fmt.Errorf("failed to generate default audit policy: %w", err)
	}
	if err := os.WriteFile(auditPolicyPath, auditPolicy, 0o644); err != nil {
		return fmt.Errorf("failed to write default audit policy: %w", err)
	}

	initConfigFile, err := os.CreateTemp("", "kubeadm-init.*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create init config file %v: %w", initConfigFile.Name(), err)
	}
	defer os.Remove(initConfigFile.Name())

	if _, err := initConfigFile.Write(initConfig); err != nil {
		return fmt.Errorf("writing kubeadm init yaml config %v failed: %w", initConfigFile.Name(), err)
	}

	cmd := exec.Command(kubeadmPath, "init", "--config", initConfigFile.Name())
	_, err = cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("kubeadm init failed (code %v) with: %s", exitErr.ExitCode(), exitErr.Stderr)
		}
		return fmt.Errorf("kubeadm init failed: %w", err)
	}
	return nil
}

// SetupPodNetwork sets up the flannel pod network.
func (k *KubernetesUtil) SetupPodNetwork(kubectl Client, podNetworkConfiguration resources.Marshaler) error {
	if err := kubectl.Apply(podNetworkConfiguration, true); err != nil {
		return err
	}

	// allow coredns to run on uninitialized nodes (required by cloud-controller-manager)
	err := exec.Command(kubectlPath, "--kubeconfig", kubeConfig, "-n", "kube-system", "patch", "deployment", "coredns", "--type", "json", "-p", "[{\"op\":\"add\",\"path\":\"/spec/template/spec/tolerations/-\",\"value\":{\"key\":\"node.cloudprovider.kubernetes.io/uninitialized\",\"value\":\"true\",\"effect\":\"NoSchedule\"}}]").Run()
	if err != nil {
		return err
	}
	return exec.Command(kubectlPath, "--kubeconfig", kubeConfig, "-n", "kube-system", "patch", "deployment", "coredns", "--type", "json", "-p", "[{\"op\":\"add\",\"path\":\"/spec/template/spec/tolerations/-\",\"value\":{\"key\":\"node.kubernetes.io/network-unavailable\",\"value\":\"\",\"effect\":\"NoSchedule\"}}]").Run()
}

// SetupAutoscaling deploys the k8s cluster autoscaler.
func (k *KubernetesUtil) SetupAutoscaling(kubectl Client, clusterAutoscalerConfiguration resources.Marshaler, secrets resources.Marshaler) error {
	if err := kubectl.Apply(secrets, true); err != nil {
		return fmt.Errorf("applying cluster-autoscaler Secrets failed: %w", err)
	}
	return kubectl.Apply(clusterAutoscalerConfiguration, true)
}

// SetupCloudControllerManager deploys the k8s cloud-controller-manager.
func (k *KubernetesUtil) SetupCloudControllerManager(kubectl Client, cloudControllerManagerConfiguration resources.Marshaler, configMaps resources.Marshaler, secrets resources.Marshaler) error {
	if err := kubectl.Apply(configMaps, true); err != nil {
		return fmt.Errorf("applying ccm ConfigMaps failed: %w", err)
	}
	if err := kubectl.Apply(secrets, true); err != nil {
		return fmt.Errorf("applying ccm Secrets failed: %w", err)
	}
	if err := kubectl.Apply(cloudControllerManagerConfiguration, true); err != nil {
		return fmt.Errorf("applying ccm failed: %w", err)
	}
	return nil
}

// SetupCloudNodeManager deploys the k8s cloud-node-manager.
func (k *KubernetesUtil) SetupCloudNodeManager(kubectl Client, cloudNodeManagerConfiguration resources.Marshaler) error {
	return kubectl.Apply(cloudNodeManagerConfiguration, true)
}

// JoinCluster joins existing Kubernetes cluster using kubeadm join.
func (k *KubernetesUtil) JoinCluster(joinConfig []byte) error {
	// TODO: audit policy should be user input
	auditPolicy, err := resources.NewDefaultAuditPolicy().Marshal()
	if err != nil {
		return fmt.Errorf("failed to generate default audit policy: %w", err)
	}
	if err := os.WriteFile(auditPolicyPath, auditPolicy, 0o644); err != nil {
		return fmt.Errorf("failed to write default audit policy: %w", err)
	}

	joinConfigFile, err := os.CreateTemp("", "kubeadm-join.*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create join config file %v: %w", joinConfigFile.Name(), err)
	}
	defer os.Remove(joinConfigFile.Name())

	if _, err := joinConfigFile.Write(joinConfig); err != nil {
		return fmt.Errorf("writing kubeadm init yaml config %v failed: %w", joinConfigFile.Name(), err)
	}

	// run `kubeadm join` to join a worker node to an existing Kubernetes cluster
	cmd := exec.Command(kubeadmPath, "join", "--config", joinConfigFile.Name())
	if _, err := cmd.Output(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("kubeadm join failed (code %v) with: %s", exitErr.ExitCode(), exitErr.Stderr)
		}
		return fmt.Errorf("kubeadm join failed: %w", err)
	}
	return nil
}

// StartKubelet enables and starts the kubelet systemd unit.
func (k *KubernetesUtil) StartKubelet() error {
	ctx, cancel := context.WithTimeout(context.TODO(), kubeletStartTimeout)
	defer cancel()
	if err := enableSystemdUnit(ctx, kubeletServiceEtcPath); err != nil {
		return fmt.Errorf("enabling kubelet systemd unit failed: %w", err)
	}
	return startSystemdUnit(ctx, "kubelet.service")
}

// RestartKubelet restarts a kubelet.
func (k *KubernetesUtil) RestartKubelet() error {
	ctx, cancel := context.WithTimeout(context.TODO(), kubeletStartTimeout)
	defer cancel()
	return restartSystemdUnit(ctx, "kubelet.service")
}

// GetControlPlaneJoinCertificateKey return the key which can be used in combination with the joinArgs
// to join the Cluster as control-plane.
func (k *KubernetesUtil) GetControlPlaneJoinCertificateKey() (string, error) {
	// Key will be valid for 1h (no option to reduce the duration).
	// https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-init-phase/#cmd-phase-upload-certs
	output, err := exec.Command(kubeadmPath, "init", "phase", "upload-certs", "--upload-certs").Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("kubeadm upload-certs failed (code %v) with: %s", exitErr.ExitCode(), exitErr.Stderr)
		}
		return "", fmt.Errorf("kubeadm upload-certs failed: %w", err)
	}
	// Example output:
	/*
		[upload-certs] Storing the certificates in ConfigMap "kubeadm-certs" in the "kube-system" Namespace
		[upload-certs] Using certificate key:
		9555b74008f24687eb964bd90a164ecb5760a89481d9c55a77c129b7db438168
	*/
	key := regexp.MustCompile("[a-f0-9]{64}").FindString(string(output))
	if key == "" {
		return "", fmt.Errorf("failed to parse kubeadm output: %s", string(output))
	}
	return key, nil
}

// CreateJoinToken creates a new bootstrap (join) token.
func (k *KubernetesUtil) CreateJoinToken(ttl time.Duration) (*kubeadm.BootstrapTokenDiscovery, error) {
	output, err := exec.Command(kubeadmPath, "token", "create", "--ttl", ttl.String(), "--print-join-command").Output()
	if err != nil {
		return nil, fmt.Errorf("kubeadm token create failed: %w", err)
	}
	// `kubeadm token create [...] --print-join-command` outputs the following format:
	// kubeadm join [API_SERVER_ENDPOINT] --token [TOKEN] --discovery-token-ca-cert-hash [DISCOVERY_TOKEN_CA_CERT_HASH]
	return ParseJoinCommand(string(output))
}
