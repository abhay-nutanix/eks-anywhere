package validations

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	eksdv1alpha1 "github.com/aws/eks-distro-build-tooling/release/api/v1alpha1"
	"sigs.k8s.io/yaml"

	"github.com/aws/eks-anywhere/pkg/api/v1alpha1"
	"github.com/aws/eks-anywhere/pkg/clients/kubernetes"
	"github.com/aws/eks-anywhere/pkg/cluster"
	"github.com/aws/eks-anywhere/pkg/config"
	"github.com/aws/eks-anywhere/pkg/constants"
	"github.com/aws/eks-anywhere/pkg/logger"
	"github.com/aws/eks-anywhere/pkg/manifests"
	"github.com/aws/eks-anywhere/pkg/manifests/bundles"
	"github.com/aws/eks-anywhere/pkg/providers"
	"github.com/aws/eks-anywhere/pkg/providers/common"
	"github.com/aws/eks-anywhere/pkg/semver"
	"github.com/aws/eks-anywhere/pkg/types"
	"github.com/aws/eks-anywhere/pkg/utils/ptr"
	releasev1alpha1 "github.com/aws/eks-anywhere/release/api/v1alpha1"
)

const (
	supportedManagementComponentsMinorVersionIncrement int64 = 1
	releaseV022                                              = "v0.22.0"
)

// ValidateOSForRegistryMirror checks if the OS is valid for the provided registry mirror configuration.
func ValidateOSForRegistryMirror(clusterSpec *cluster.Spec, provider providers.Provider) error {
	cluster := clusterSpec.Cluster
	if cluster.Spec.RegistryMirrorConfiguration == nil {
		return nil
	}

	machineConfigs := provider.MachineConfigs(clusterSpec)
	if machineConfigs == nil {
		return nil
	}

	for _, mc := range machineConfigs {
		if mc.OSFamily() == v1alpha1.Bottlerocket && cluster.Spec.RegistryMirrorConfiguration.InsecureSkipVerify {
			return errors.New("InsecureSkipVerify is not supported for bottlerocket")
		}
	}

	ociNamespaces := cluster.Spec.RegistryMirrorConfiguration.OCINamespaces
	if len(ociNamespaces) == 0 {
		return nil
	}

	return nil
}

func ValidateCertForRegistryMirror(clusterSpec *cluster.Spec, tlsValidator TlsValidator) error {
	cluster := clusterSpec.Cluster
	if cluster.Spec.RegistryMirrorConfiguration == nil {
		return nil
	}

	if cluster.Spec.RegistryMirrorConfiguration.InsecureSkipVerify {
		logger.V(1).Info("Warning: skip registry certificate verification is enabled", "registryMirrorConfiguration.insecureSkipVerify", true)
		return nil
	}

	host, port := cluster.Spec.RegistryMirrorConfiguration.Endpoint, cluster.Spec.RegistryMirrorConfiguration.Port
	authorityUnknown, err := tlsValidator.IsSignedByUnknownAuthority(host, port)
	if err != nil {
		return fmt.Errorf("validating registry mirror endpoint: %v", err)
	}
	if authorityUnknown {
		logger.V(1).Info(fmt.Sprintf("Warning: registry mirror endpoint %s is using self-signed certs", cluster.Spec.RegistryMirrorConfiguration.Endpoint))
	}

	certContent := cluster.Spec.RegistryMirrorConfiguration.CACertContent
	if certContent == "" && authorityUnknown {
		return fmt.Errorf("registry %s is using self-signed certs, please provide the certificate using caCertContent field. Or use insecureSkipVerify field to skip registry certificate verification", cluster.Spec.RegistryMirrorConfiguration.Endpoint)
	}

	if certContent != "" {
		if err = tlsValidator.ValidateCert(host, port, certContent); err != nil {
			return fmt.Errorf("invalid registry certificate: %v", err)
		}
	}

	return nil
}

// ValidateAuthenticationForRegistryMirror checks if REGISTRY_USERNAME and REGISTRY_PASSWORD is set if authenticated registry mirrors are used.
func ValidateAuthenticationForRegistryMirror(clusterSpec *cluster.Spec) error {
	cluster := clusterSpec.Cluster
	if cluster.Spec.RegistryMirrorConfiguration != nil && cluster.Spec.RegistryMirrorConfiguration.Authenticate {
		_, _, err := config.ReadCredentials()
		if err != nil {
			return err
		}
	}
	return nil
}

// ValidateManagementClusterName checks if the management cluster specified in the workload cluster spec is valid.
func ValidateManagementClusterName(ctx context.Context, k KubectlClient, mgmtCluster *types.Cluster, mgmtClusterName string) error {
	cluster, err := k.GetEksaCluster(ctx, mgmtCluster, mgmtClusterName)
	if err != nil {
		return err
	}
	if cluster.IsManaged() {
		return fmt.Errorf("%s is not a valid management cluster", mgmtClusterName)
	}
	return nil
}

// ValidateEksaVersion ensures that the version matches EKS-A CLI.
func ValidateEksaVersion(ctx context.Context, cliVersion string, workload *cluster.Spec) error {
	v := workload.Cluster.Spec.EksaVersion

	if v == nil {
		return nil
	}

	parsedVersion, err := semver.New(string(*v))
	if err != nil {
		return fmt.Errorf("parsing cluster eksa version: %v", err)
	}

	parsedCLIVersion, err := semver.New(cliVersion)
	if err != nil {
		return fmt.Errorf("parsing eksa cli version: %v", err)
	}

	if !parsedVersion.SamePatch(parsedCLIVersion) {
		return fmt.Errorf("cluster's eksaVersion does not match EKS-Anywhere CLI's version")
	}

	return nil
}

// ValidateEksaVersionSkew ensures that upgrades are sequential by CLI minor versions.
func ValidateEksaVersionSkew(ctx context.Context, k KubectlClient, mgmtCluster *types.Cluster, spec *cluster.Spec) error {
	currentCluster, err := k.GetEksaCluster(ctx, mgmtCluster, spec.Cluster.Name)
	if err != nil {
		return err
	}

	return v1alpha1.ValidateEksaVersionSkew(spec.Cluster, currentCluster).ToAggregate()
}

// ValidateManagementClusterEksaVersion ensures workload cluster isn't created by a newer version than management cluster.
func ValidateManagementClusterEksaVersion(ctx context.Context, k KubectlClient, mgmtCluster *types.Cluster, workload *cluster.Spec) error {
	mgmt, err := k.GetEksaCluster(ctx, mgmtCluster, mgmtCluster.Name)
	if err != nil {
		return err
	}

	return ValidateManagementEksaVersion(mgmt, workload.Cluster)
}

// ValidateManagementEksaVersion ensures a workload cluster's EksaVersion is not greater than a management cluster's version.
func ValidateManagementEksaVersion(mgmtCluster, cluster *v1alpha1.Cluster) error {
	if !clustersHaveEksaVersion(mgmtCluster, cluster) {
		return nil
	}

	mVersion, wVersion, err := parseClusterEksaVersion(mgmtCluster, cluster)
	if err != nil {
		return err
	}

	devBuildVersion, _ := semver.New(v1alpha1.DevBuildVersion)
	if mVersion.SamePatch(devBuildVersion) {
		return nil
	}

	if wVersion.GreaterThan(mVersion) {
		errMsg := fmt.Sprintf("cannot upgrade workload cluster to %v while management cluster is an older version: %v", wVersion, mVersion)
		reason := v1alpha1.EksaVersionInvalidReason
		cluster.Status.FailureMessage = ptr.String(errMsg)
		cluster.Status.FailureReason = &reason
		return errors.New(errMsg)
	}

	// reset failure message if old matches this validation
	oldFailure := cluster.Status.FailureReason
	if oldFailure != nil && *oldFailure == v1alpha1.EksaVersionInvalidReason {
		cluster.Status.FailureMessage = nil
		cluster.Status.FailureReason = nil
	}
	return nil
}

func clustersHaveEksaVersion(mgmtCluster, cluster *v1alpha1.Cluster) bool {
	if cluster.Spec.BundlesRef != nil {
		return false
	}

	if cluster.Spec.EksaVersion == nil && mgmtCluster.Spec.EksaVersion == nil {
		return false
	}

	return true
}

func parseClusterEksaVersion(mgmtCluster, cluster *v1alpha1.Cluster) (*semver.Version, *semver.Version, error) {
	if cluster.Spec.EksaVersion == nil {
		return nil, nil, fmt.Errorf("cluster has nil EksaVersion")
	}

	if mgmtCluster.Spec.EksaVersion == nil {
		return nil, nil, fmt.Errorf("management cluster has nil EksaVersion")
	}

	mVersion, err := semver.New(string(*mgmtCluster.Spec.EksaVersion))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing management EksaVersion: %v", err)
	}

	wVersion, err := semver.New(string(*cluster.Spec.EksaVersion))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing workload EksaVersion: %v", err)
	}

	return mVersion, wVersion, nil
}

// ValidateEksaReleaseExistOnManagement checks if there is a corresponding eksareleases CR for workload's eksaVersion on the mgmt cluster.
func ValidateEksaReleaseExistOnManagement(ctx context.Context, k kubernetes.Client, workload *v1alpha1.Cluster) error {
	v := workload.Spec.EksaVersion
	err := k.Get(ctx, releasev1alpha1.GenerateEKSAReleaseName(string(*v)), constants.EksaSystemNamespace, &releasev1alpha1.EKSARelease{})
	if err != nil {
		return err
	}
	return nil
}

// ValidatePauseAnnotation checks if the target cluster has annotation anywhere.eks.amazonaws.com/paused set to true or not.
func ValidatePauseAnnotation(ctx context.Context, k KubectlClient, cluster *types.Cluster, clusterName string) error {
	currentCluster, err := k.GetEksaCluster(ctx, cluster, clusterName)
	if err != nil {
		return err
	}
	if currentCluster.IsReconcilePaused() {
		return fmt.Errorf("cluster cannot be upgraded with paused cluster controller reconciler")
	}
	return nil
}

// ValidateManagementComponentsVersionSkew checks if the management components version is only one minor version greater than the cluster version.
func ValidateManagementComponentsVersionSkew(ctx context.Context, k KubectlClient, mgmtCluster *types.Cluster, eksaRelease *releasev1alpha1.EKSARelease) error {
	mgmt, err := k.GetEksaCluster(ctx, mgmtCluster, mgmtCluster.Name)
	if err != nil {
		return err
	}

	newManagementComponentsSemVer, err := semver.New(string(eksaRelease.Spec.Version))
	if err != nil {
		return fmt.Errorf("parsing management components version: %v", err)
	}

	if mgmt.Spec.EksaVersion == nil {
		return fmt.Errorf("management cluster EksaVersion not specified")
	}

	managementClusterSemVer, err := semver.New(string(*mgmt.Spec.EksaVersion))
	if err != nil {
		return fmt.Errorf("parsing management components version: %v", err)
	}

	majorVersionDifference := int64(newManagementComponentsSemVer.Major) - int64(managementClusterSemVer.Major)
	minorVersionDifference := int64(newManagementComponentsSemVer.Minor) - int64(managementClusterSemVer.Minor)

	if majorVersionDifference != 0 || minorVersionDifference > supportedManagementComponentsMinorVersionIncrement {
		return fmt.Errorf("management components version %s can only be one minor version greater than cluster version %s", newManagementComponentsSemVer, managementClusterSemVer)
	}
	return nil
}

// ValidateBottlerocketKubeletConfig validates bottlerocket settings for Kubelet Configuration.
func ValidateBottlerocketKubeletConfig(spec *cluster.Spec) error {
	cpKubeletConfig := spec.Cluster.Spec.ControlPlaneConfiguration.KubeletConfiguration
	if _, err := common.ConvertToBottlerocketKubernetesSettings(cpKubeletConfig); err != nil {
		return err
	}

	workerNodeGroupConfigs := spec.Cluster.Spec.WorkerNodeGroupConfigurations
	for _, workerNodeGroupConfig := range workerNodeGroupConfigs {
		wnKubeletConfig := workerNodeGroupConfig.KubeletConfiguration
		if _, err := common.ConvertToBottlerocketKubernetesSettings(wnKubeletConfig); err != nil {
			return err
		}
	}

	return nil
}

// ValidateExtendedKubernetesVersionSupport validates the extended kubernetes version support for create and upgrade operations.
func ValidateExtendedKubernetesVersionSupport(ctx context.Context, clusterSpec v1alpha1.Cluster, reader *manifests.Reader, k kubernetes.Client, bundlesOverride string) error {
	if clusterSpec.Spec.DatacenterRef.Kind == "SnowDatacenterConfig" {
		return nil
	}
	var b *releasev1alpha1.Bundles
	var err error
	if bundlesOverride != "" {
		b, err = bundles.Read(reader, bundlesOverride)
		if err != nil {
			return fmt.Errorf("getting bundle for cluster: %w", err)
		}
	} else {
		eksaVersion := clusterSpec.Spec.EksaVersion
		skip, err := ShouldSkipBundleSignatureValidation((*string)(eksaVersion))
		if err != nil {
			return err
		}
		// Skip the signature validation for those versions prior to 'v0.22.0'
		if skip {
			return nil
		}
		b, err = reader.ReadBundlesForVersion(string(*eksaVersion))
		if err != nil {
			return fmt.Errorf("getting bundle for cluster: %w", err)
		}
	}

	// Get the release manifest from the bundle
	releaseManifest, err := getReleaseManifestFromBundle(clusterSpec, b)
	if err != nil {
		return fmt.Errorf("getting release manifest: %w", err)
	}

	return ValidateExtendedK8sVersionSupport(ctx, clusterSpec, b, releaseManifest, k)
}

// getReleaseManifestFromBundle retrieves the EKS Distro release manifest from the bundle.
// For airgapped clusters, it reads from a local file path.
// For non-airgapped clusters, it fetches from the public URL.
func getReleaseManifestFromBundle(clusterSpec v1alpha1.Cluster, bundle *releasev1alpha1.Bundles) (*eksdv1alpha1.Release, error) {
	versionsBundle, err := cluster.GetVersionsBundle(clusterSpec.Spec.KubernetesVersion, bundle)
	if err != nil {
		return nil, fmt.Errorf("getting versions bundle for %s kubernetes version: %w", clusterSpec.Spec.KubernetesVersion, err)
	}

	releaseManifest := &eksdv1alpha1.Release{}

	// Check if this is an airgapped cluster (EksDReleaseUrl points to local path)
	if strings.Contains(versionsBundle.EksD.EksDReleaseUrl, "eks-anywhere-downloads") {
		// Airgapped case: read from local file path
		releaseManifestFilePath := versionsBundle.EksD.EksDReleaseUrl
		contents, err := os.ReadFile(releaseManifestFilePath)
		if err != nil {
			return nil, fmt.Errorf("reading eksd release manifest file: %w", err)
		}
		if err := yaml.Unmarshal(contents, releaseManifest); err != nil {
			return nil, fmt.Errorf("unmarshalling eksd release manifest file: %w", err)
		}
	} else {
		// Non-airgapped case: fetch from public URL
		resp, err := http.Get(versionsBundle.EksD.EksDReleaseUrl)
		if err != nil {
			return nil, fmt.Errorf("fetching eksd release manifest from URL %s: %w", versionsBundle.EksD.EksDReleaseUrl, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetching eksd release manifest from URL %s: received status code %d", versionsBundle.EksD.EksDReleaseUrl, resp.StatusCode)
		}

		contents, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading eksd release manifest response body: %w", err)
		}

		if err := yaml.Unmarshal(contents, releaseManifest); err != nil {
			return nil, fmt.Errorf("unmarshalling eksd release manifest from URL: %w", err)
		}
	}

	return releaseManifest, nil
}
