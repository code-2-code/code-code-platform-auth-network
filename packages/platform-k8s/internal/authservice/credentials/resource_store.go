package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"code-code.internal/go-contract/domainerror"
	domaineventv1 "code-code.internal/go-contract/platform/domain_event/v1"
	platformv1alpha1 "code-code.internal/platform-k8s/api/v1alpha1"
	"code-code.internal/platform-k8s/internal/platform/resourceops"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const credentialTableName = "platform_credentials"

// ResourceStore owns CredentialDefinitionResource persistence for auth-service.
type ResourceStore interface {
	List(ctx context.Context) ([]platformv1alpha1.CredentialDefinitionResource, error)
	Get(ctx context.Context, credentialID string) (*platformv1alpha1.CredentialDefinitionResource, error)
	Create(ctx context.Context, resource *platformv1alpha1.CredentialDefinitionResource) error
	Upsert(ctx context.Context, resource *platformv1alpha1.CredentialDefinitionResource) error
	Update(ctx context.Context, credentialID string, mutate func(*platformv1alpha1.CredentialDefinitionResource) error) error
	UpdateStatus(ctx context.Context, credentialID string, mutate func(*platformv1alpha1.CredentialDefinitionResource) error) error
	Delete(ctx context.Context, credentialID string) error
}

type kubernetesResourceStore struct {
	client    ctrlclient.Client
	namespace string
}

func NewKubernetesResourceStore(client ctrlclient.Client, namespace string) (ResourceStore, error) {
	if client == nil {
		return nil, fmt.Errorf("credentials: resource store client is nil")
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return nil, fmt.Errorf("credentials: resource store namespace is empty")
	}
	return kubernetesResourceStore{client: client, namespace: namespace}, nil
}

func (s kubernetesResourceStore) List(ctx context.Context) ([]platformv1alpha1.CredentialDefinitionResource, error) {
	list := &platformv1alpha1.CredentialDefinitionResourceList{}
	if err := s.client.List(ctx, list, ctrlclient.InNamespace(s.namespace)); err != nil {
		return nil, err
	}
	return append([]platformv1alpha1.CredentialDefinitionResource(nil), list.Items...), nil
}

func (s kubernetesResourceStore) Get(ctx context.Context, credentialID string) (*platformv1alpha1.CredentialDefinitionResource, error) {
	resource := &platformv1alpha1.CredentialDefinitionResource{}
	if err := s.client.Get(ctx, credentialObjectKey(s.namespace, credentialID), resource); err != nil {
		return nil, err
	}
	return resource, nil
}

func (s kubernetesResourceStore) Create(ctx context.Context, resource *platformv1alpha1.CredentialDefinitionResource) error {
	return resourceops.CreateResource(ctx, s.client, resource, s.namespace, resource.Name)
}

func (s kubernetesResourceStore) Upsert(ctx context.Context, resource *platformv1alpha1.CredentialDefinitionResource) error {
	return resourceops.UpsertResource(ctx, s.client, resource, s.namespace, resource.Name)
}

func (s kubernetesResourceStore) Update(ctx context.Context, credentialID string, mutate func(*platformv1alpha1.CredentialDefinitionResource) error) error {
	return resourceops.UpdateResource(ctx, s.client, credentialObjectKey(s.namespace, credentialID), mutate, func() *platformv1alpha1.CredentialDefinitionResource {
		return &platformv1alpha1.CredentialDefinitionResource{}
	})
}

func (s kubernetesResourceStore) UpdateStatus(ctx context.Context, credentialID string, mutate func(*platformv1alpha1.CredentialDefinitionResource) error) error {
	return resourceops.UpdateStatus(ctx, s.client, credentialObjectKey(s.namespace, credentialID), mutate, func() *platformv1alpha1.CredentialDefinitionResource {
		return &platformv1alpha1.CredentialDefinitionResource{}
	})
}

func (s kubernetesResourceStore) Delete(ctx context.Context, credentialID string) error {
	return resourceops.DeleteResource(ctx, s.client, &platformv1alpha1.CredentialDefinitionResource{}, s.namespace, strings.TrimSpace(credentialID))
}

type credentialRowScanner interface {
	Scan(...any) error
}

func scanCredentialResource(row credentialRowScanner) (*platformv1alpha1.CredentialDefinitionResource, error) {
	var payload []byte
	var generation int64
	if err := row.Scan(&payload, &generation); err != nil {
		return nil, fmt.Errorf("credentials: scan credential record: %w", err)
	}
	return decodeCredentialResource(payload, generation)
}

func decodeCredentialResource(payload []byte, generation int64) (*platformv1alpha1.CredentialDefinitionResource, error) {
	resource := &platformv1alpha1.CredentialDefinitionResource{}
	if err := json.Unmarshal(payload, resource); err != nil {
		return nil, fmt.Errorf("credentials: decode credential record: %w", err)
	}
	resource.SetGeneration(generation)
	resource.SetResourceVersion(strconv.FormatInt(generation, 10))
	return resource, nil
}

func encodeCredentialResource(resource *platformv1alpha1.CredentialDefinitionResource) (string, error) {
	payload, err := json.Marshal(resource)
	if err != nil {
		return "", fmt.Errorf("credentials: encode credential record %q: %w", resource.GetName(), err)
	}
	return string(payload), nil
}

func normalizeCredentialResource(resource *platformv1alpha1.CredentialDefinitionResource, namespace string, generation int64) error {
	if resource == nil {
		return domainerror.NewValidation("credentials: credential resource is nil")
	}
	if strings.TrimSpace(resource.Name) == "" {
		return domainerror.NewValidation("credentials: credential resource name is empty")
	}
	resource.Namespace = strings.TrimSpace(namespace)
	if resource.CreationTimestamp.Time.IsZero() {
		resource.CreationTimestamp = metav1.NewTime(time.Now().UTC())
	}
	if generation <= 0 {
		generation = 1
	}
	resource.Generation = generation
	resource.ResourceVersion = strconv.FormatInt(generation, 10)
	return nil
}

func credentialMutation(value string) domaineventv1.DomainMutation {
	switch strings.TrimSpace(value) {
	case "created":
		return domaineventv1.DomainMutation_DOMAIN_MUTATION_CREATED
	case "status_updated":
		return domaineventv1.DomainMutation_DOMAIN_MUTATION_STATUS_UPDATED
	case "deleted":
		return domaineventv1.DomainMutation_DOMAIN_MUTATION_DELETED
	default:
		return domaineventv1.DomainMutation_DOMAIN_MUTATION_UPDATED
	}
}

func credentialNotFound(name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "platform.code-code.internal", Resource: "credentialdefinitions"}, strings.TrimSpace(name))
}

func credentialObjectKey(namespace string, credentialID string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: strings.TrimSpace(credentialID)}
}
