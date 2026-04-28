package egresspolicies

import (
	"context"
	"fmt"
	"strings"

	egressv1 "code-code.internal/go-contract/egress/v1"
	"google.golang.org/protobuf/encoding/protojson"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var policyJSON = protojson.MarshalOptions{
	UseProtoNames:   true,
	EmitUnpopulated: true,
}

var policyJSONRead = protojson.UnmarshalOptions{}

func (s *Service) loadPolicy(ctx context.Context) (*egressv1.EgressPolicy, error) {
	config := &corev1.ConfigMap{}
	if err := s.reader.Get(ctx, types.NamespacedName{Namespace: s.namespace, Name: policyConfigMapName}, config); err != nil {
		if apierrors.IsNotFound(err) {
			return defaultPolicy(), nil
		}
		return nil, fmt.Errorf("read egress policy config: %w", err)
	}
	payload := strings.TrimSpace(config.Data[policyConfigKey])
	if payload == "" {
		return nil, fmt.Errorf("egress policy config %s/%s has no %s", s.namespace, policyConfigMapName, policyConfigKey)
	}
	policy := &egressv1.EgressPolicy{}
	if err := policyJSONRead.Unmarshal([]byte(payload), policy); err != nil {
		return nil, fmt.Errorf("parse egress policy config %s/%s key %s: %w", s.namespace, policyConfigMapName, policyConfigKey, err)
	}
	return normalizePolicy(policy)
}

func (s *Service) savePolicy(ctx context.Context, policy *egressv1.EgressPolicy) error {
	normalized, err := normalizePolicy(policy)
	if err != nil {
		return err
	}
	payload, err := policyJSON.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("marshal egress policy: %w", err)
	}
	config := &corev1.ConfigMap{}
	key := types.NamespacedName{Namespace: s.namespace, Name: policyConfigMapName}
	if err := s.client.Get(ctx, key, config); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("read egress policy config: %w", err)
		}
		config = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: s.namespace,
				Name:      policyConfigMapName,
				Labels:    mergeStringMaps(gatewayLabels(), map[string]string{labelEgressRole: egressRolePolicy}),
			},
			Data: map[string]string{policyConfigKey: string(payload)},
		}
		if err := s.client.Create(ctx, config); err != nil {
			return fmt.Errorf("create egress policy config: %w", err)
		}
		return nil
	}
	original := config.DeepCopy()
	config.Labels = mergeStringMaps(config.Labels, gatewayLabels(), map[string]string{labelEgressRole: egressRolePolicy})
	if config.Data == nil {
		config.Data = map[string]string{}
	}
	config.Data[policyConfigKey] = string(payload)
	if err := s.client.Patch(ctx, config, ctrlclient.MergeFrom(original)); err != nil {
		return fmt.Errorf("patch egress policy config: %w", err)
	}
	return nil
}
