module code-code.internal/platform-contract

go 1.26.2

require (
	code-code.internal/agent-runtime-contract v0.0.0
	code-code.internal/go-contract v0.0.0
)

require (
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace code-code.internal/agent-runtime-contract => ../agent-runtime-contract

replace code-code.internal/go-contract => ../go-contract
