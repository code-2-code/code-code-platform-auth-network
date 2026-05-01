# Agent Rules

- This repository owns credential, OAuth, egress policy, and egress auth behavior only.
- Do not edit protobuf source or generated contracts here; change `code-code-contracts` first.
- Do not add provider orchestration, model catalog, agent runtime, profile, notification, or deployment behavior here.
- Never log, test, document, or persist credential material, OAuth codes, tokens, client secrets, cookies, or private key material.
- Run the auth-network service tests before delivery.
