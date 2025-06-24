/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/golang-jwt/jwt/v5"
	authaws "github.com/hashicorp/vault/api/auth/aws"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/constants"
	"github.com/external-secrets/external-secrets/pkg/metrics"
	vaultiamauth "github.com/external-secrets/external-secrets/pkg/provider/vault/iamauth"
	"github.com/external-secrets/external-secrets/pkg/provider/vault/util"
)

const (
	defaultAWSRegion                = "us-east-1"
	defaultAWSAuthMountPath         = "aws"
	errIrsaTokenEnvVarNotFoundOnPod = "expected env variable: %s not found on controller's pod"
	errIrsaTokenFileNotFoundOnPod   = "web identity token file not found at %s location: %w"
	errIrsaTokenFileNotReadable     = "could not read the web identity token from the file %s: %w"
	errIrsaTokenNotValidJWT         = "could not parse web identity token available at %s. not a valid jwt?: %w"
	errPodInfoNotFoundOnToken       = "could not find pod identity info on token %s: %w"
	errPodAuthTypeUnknown           = "no AWS auth type detected"
	errInvalidAuthConfiguration     = "invalid authentication configuration: %s"
)

// AuthType represents the type of AWS authentication being used
type AuthType string

const (
	AuthTypeIRSA        AuthType = "irsa"
	AuthTypePodIdentity AuthType = "pod-identity"
	AuthTypeUnknown     AuthType = "unknown"
)

// PodIdentityInfo contains information extracted from the pod identity token
type PodIdentityInfo struct {
	Namespace      string
	ServiceAccount string
}

func setIamAuthToken(ctx context.Context, v *client, jwtProvider util.JwtProviderFactory, assumeRoler vaultiamauth.STSProvider) (bool, error) {
	iamAuth := v.store.Auth.Iam
	isClusterKind := v.storeKind == esv1.ClusterSecretStoreKind
	if iamAuth != nil {
		err := v.requestTokenWithIamAuth(ctx, iamAuth, isClusterKind, v.kube, v.namespace, jwtProvider, assumeRoler)
		if err != nil {
			return true, err
		}
		return true, nil
	}
	return false, nil
}

// detectAuthType determines the type of AWS authentication available on the pod
func detectAuthType() (AuthType, error) {
	irsaTokenFile, irsaTokenFileOk := os.LookupEnv(vaultiamauth.AWSWebIdentityTokenFileEnvVar)
	containerAuthTokenFile, containerAuthTokenFileOk := os.LookupEnv(vaultiamauth.AWSContainerAuthorizationTokenFileEnvVar)
	containerAuthToken, containerAuthTokenOk := os.LookupEnv(vaultiamauth.AWSContainerAuthorizationTokenEnvVar)

	if !irsaTokenFileOk && !containerAuthTokenFileOk && !containerAuthTokenOk {
		return AuthTypeUnknown, fmt.Errorf(errPodAuthTypeUnknown)
	}

	if irsaTokenFile != "" {
		return AuthTypeIRSA, nil
	}

	if containerAuthTokenFile != "" && containerAuthToken != "" {
		return AuthTypePodIdentity, nil
	}

	return AuthTypeUnknown, fmt.Errorf(errInvalidAuthConfiguration, "invalid authentication")
}

// getJwtToken retrieves the JWT token based on the authentication type
func getJwtToken(authType AuthType) (string, error) {
	switch authType {
	case AuthTypeIRSA:
		irsaTokenFile, _ := os.LookupEnv(vaultiamauth.AWSWebIdentityTokenFileEnvVar)
		if _, err := os.Stat(irsaTokenFile); err != nil {
			return "", fmt.Errorf(errIrsaTokenFileNotFoundOnPod, irsaTokenFile, err)
		}
		tokenBytes, err := os.ReadFile(filepath.Clean(irsaTokenFile))
		if err != nil {
			return "", fmt.Errorf(errIrsaTokenFileNotReadable, irsaTokenFile, err)
		}
		return string(tokenBytes), nil

	case AuthTypePodIdentity:
		containerAuthTokenFile, _ := os.LookupEnv(vaultiamauth.AWSContainerAuthorizationTokenFileEnvVar)
		if _, err := os.Stat(containerAuthTokenFile); err != nil {
			return "", fmt.Errorf(errIrsaTokenFileNotFoundOnPod, containerAuthTokenFile, err)
		}
		tokenBytes, err := os.ReadFile(filepath.Clean(containerAuthTokenFile))
		if err != nil {
			return "", fmt.Errorf(errIrsaTokenFileNotReadable, containerAuthTokenFile, err)
		}
		return string(tokenBytes), nil

	default:
		return "", fmt.Errorf(errPodAuthTypeUnknown)
	}
}

// parsePodIdentityInfo extracts namespace and service account information from the JWT token
func parsePodIdentityInfo(tokenString string) (*PodIdentityInfo, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf(errIrsaTokenNotValidJWT, tokenString, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf(errPodInfoNotFoundOnToken, tokenString, err)
	}

	// Extract kubernetes.io namespace and serviceaccount from JWT claims
	k8sClaims, ok := claims["kubernetes.io"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf(errPodInfoNotFoundOnToken, tokenString, err)
	}

	namespace, ok := k8sClaims["namespace"].(string)
	if !ok {
		return nil, fmt.Errorf(errPodInfoNotFoundOnToken, tokenString, err)
	}

	saClaims, ok := k8sClaims["serviceaccount"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf(errPodInfoNotFoundOnToken, tokenString, err)
	}

	serviceAccount, ok := saClaims["name"].(string)
	if !ok {
		return nil, fmt.Errorf(errPodInfoNotFoundOnToken, tokenString, err)
	}

	return &PodIdentityInfo{
		Namespace:      namespace,
		ServiceAccount: serviceAccount,
	}, nil
}

// validateIamAuthConfiguration validates the IAM authentication configuration
func validateIamAuthConfiguration(iamAuth *esv1.VaultIamAuth) error {
	if iamAuth == nil {
		return fmt.Errorf(errInvalidAuthConfiguration, "IAM auth configuration is nil")
	}

	// Check if at least one authentication method is configured
	hasJwtAuth := iamAuth.JWTAuth != nil
	hasSecretRef := iamAuth.SecretRef != nil
	hasControllerIdentity := !hasJwtAuth && !hasSecretRef

	if !hasJwtAuth && !hasSecretRef && !hasControllerIdentity {
		return fmt.Errorf(errInvalidAuthConfiguration, "no authentication method specified (JWTAuth, SecretRef, or controller identity)")
	}

	// Validate JWT auth configuration
	if hasJwtAuth && iamAuth.JWTAuth.ServiceAccountRef == nil {
		return fmt.Errorf(errInvalidAuthConfiguration, "JWTAuth requires ServiceAccountRef")
	}

	// Validate SecretRef configuration
	if hasSecretRef {
		if iamAuth.SecretRef.AccessKeyID.Name == "" {
			return fmt.Errorf(errInvalidAuthConfiguration, "SecretRef requires AccessKeyID")
		}
		if iamAuth.SecretRef.SecretAccessKey.Name == "" {
			return fmt.Errorf(errInvalidAuthConfiguration, "SecretRef requires SecretAccessKey")
		}
	}

	return nil
}

func (c *client) requestTokenWithIamAuth(ctx context.Context, iamAuth *esv1.VaultIamAuth, isClusterKind bool, k kclient.Client, n string, jwtProvider util.JwtProviderFactory, assumeRoler vaultiamauth.STSProvider) error {
	// Validate the IAM authentication configuration
	if err := validateIamAuthConfiguration(iamAuth); err != nil {
		return err
	}

	regionAWS := defaultAWSRegion
	awsAuthMountPath := defaultAWSAuthMountPath
	if iamAuth.Region != "" {
		regionAWS = iamAuth.Region
	}
	if iamAuth.Path != "" {
		awsAuthMountPath = iamAuth.Path
	}

	var creds *credentials.Credentials
	var err error

	// Priority order: JWTAuth > SecretRef > Controller Identity
	if iamAuth.JWTAuth != nil {
		// Use credentials from explicitly defined and referenced service account
		creds, err = vaultiamauth.CredsFromServiceAccount(ctx, *iamAuth, regionAWS, isClusterKind, k, n, jwtProvider)
		if err != nil {
			return fmt.Errorf("failed to get credentials from service account: %w", err)
		}
		logger.V(1).Info("using credentials from JWTAuth service account")
	} else if iamAuth.SecretRef != nil {
		// Use credentials from SecretRef
		creds, err = vaultiamauth.CredsFromSecretRef(ctx, *iamAuth, c.storeKind, k, n)
		if err != nil {
			return fmt.Errorf("failed to get credentials from SecretRef: %w", err)
		}
		logger.V(1).Info("using credentials from SecretRef")
	} else {
		// Use controller pod's identity (IRSA or Pod Identity)
		creds, err = c.getControllerCredentials(ctx, regionAWS, k, jwtProvider)
		if err != nil {
			return fmt.Errorf("failed to get controller credentials: %w", err)
		}
		logger.V(1).Info("using controller pod credentials")
	}

	// Configure AWS session with credentials
	config := aws.NewConfig().WithEndpointResolver(vaultiamauth.ResolveEndpoint())
	if creds != nil {
		config.WithCredentials(creds)
	}
	if regionAWS != "" {
		config.WithRegion(regionAWS)
	}

	sess, err := vaultiamauth.GetAWSSession(config)
	if err != nil {
		return fmt.Errorf("failed to create AWS session: %w", err)
	}

	// Handle IAM role assumption if specified
	if iamAuth.AWSIAMRole != "" {
		stsclient := assumeRoler(sess)
		if iamAuth.ExternalID != "" {
			setExternalID := func(p *stscreds.AssumeRoleProvider) {
				p.ExternalID = aws.String(iamAuth.ExternalID)
			}
			sess.Config.WithCredentials(stscreds.NewCredentialsWithClient(stsclient, iamAuth.AWSIAMRole, setExternalID))
		} else {
			sess.Config.WithCredentials(stscreds.NewCredentialsWithClient(stsclient, iamAuth.AWSIAMRole))
		}
	}

	// Get final credentials and set environment variables
	getCreds, err := sess.Config.Credentials.Get()
	if err != nil {
		return fmt.Errorf("failed to get AWS credentials: %w", err)
	}

	// Set environment variables for Vault AWS auth
	_ = os.Setenv("AWS_ACCESS_KEY_ID", getCreds.AccessKeyID)
	_ = os.Setenv("AWS_SECRET_ACCESS_KEY", getCreds.SecretAccessKey)
	_ = os.Setenv("AWS_SESSION_TOKEN", getCreds.SessionToken)

	// Create AWS auth client and login to Vault
	var awsAuthClient *authaws.AWSAuth
	if iamAuth.VaultAWSIAMServerID != "" {
		awsAuthClient, err = authaws.NewAWSAuth(
			authaws.WithRegion(regionAWS),
			authaws.WithIAMAuth(),
			authaws.WithRole(iamAuth.Role),
			authaws.WithMountPath(awsAuthMountPath),
			authaws.WithIAMServerIDHeader(iamAuth.VaultAWSIAMServerID),
		)
	} else {
		awsAuthClient, err = authaws.NewAWSAuth(
			authaws.WithRegion(regionAWS),
			authaws.WithIAMAuth(),
			authaws.WithRole(iamAuth.Role),
			authaws.WithMountPath(awsAuthMountPath),
		)
	}

	if err != nil {
		return fmt.Errorf("failed to create AWS auth client: %w", err)
	}

	_, err = c.auth.Login(ctx, awsAuthClient)
	metrics.ObserveAPICall(constants.ProviderHCVault, constants.CallHCVaultLogin, err)
	if err != nil {
		return fmt.Errorf("failed to login to Vault: %w", err)
	}

	return nil
}

// getControllerCredentials retrieves credentials using the controller pod's identity
func (c *client) getControllerCredentials(ctx context.Context, regionAWS string, k kclient.Client, jwtProvider util.JwtProviderFactory) (*credentials.Credentials, error) {
	// Detect the authentication type available on the pod
	authType, err := detectAuthType()
	if err != nil {
		return nil, fmt.Errorf(errPodAuthTypeUnknown)
	}

	// Get the JWT token based on the authentication type
	jwtToken, err := getJwtToken(authType)
	if err != nil {
		return nil, fmt.Errorf(errIrsaTokenNotValidJWT, jwtToken, err)
	}

	// Parse pod identity information from the token
	podInfo, err := parsePodIdentityInfo(jwtToken)
	if err != nil {
		return nil, fmt.Errorf(errPodInfoNotFoundOnToken, jwtToken, err)
	}

	// Get credentials using the controller service account
	creds, err := vaultiamauth.CredsFromControllerServiceAccount(ctx, podInfo.ServiceAccount, podInfo.Namespace, regionAWS, k, jwtProvider)
	if err != nil {
		return nil, fmt.Errorf(errPodInfoNotFoundOnToken, jwtToken, err)
	}

	return creds, nil
}
