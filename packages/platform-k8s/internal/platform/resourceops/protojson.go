package resourceops

import (
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// protoMarshal converts a proto.Message to an unstructured map suitable for
// embedding inside a Kubernetes unstructured resource spec.
func ProtoMarshal(message proto.Message) (map[string]any, error) {
	raw, err := protojson.MarshalOptions{UseProtoNames: false}.Marshal(message)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
