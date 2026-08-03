# On behalf of the wrong client

This advanced FastAPI Guard policy demo uses a LangChain agent with two tools.
`get_client_record` is an unguarded read tool that returns the current actor's
structured financial record. `send_email` is wrapped with `guard_tool`, so
Arcjet evaluates the model-selected recipient and body before the simulated
email side effect can run.

The server owns the trusted mapping from the selected client to its actor ID,
record, and allowed recipients. The browser submits only `client` and
`scenario`; it cannot supply an actor, record, or allow-list.

## Configure the Console policy

Create a Guard policy with label `email.sent` and these exact inputs:

| Input | Exposure | Type |
| --- | --- | --- |
| `recipient` | Server | String |
| `allowed_recipients` | Server | String list |
| `body` | Local | String |
| `incoming_message` | Server | String |

Require an actor, then add these rules:

1. **Allowed-list membership**: require `recipient` to be a member of
   `allowed_recipients`.
2. **Sensitive info** on `body` (local SDK execution), allowing `EMAIL`,
   `GIVEN_NAME`, and `SURNAME` while denying every other detected entity type.
3. **Prompt injection** on `incoming_message` (server execution).

The example configures the Rampart sensitive-info backend. This activates the
backend-only `SSN`, `BANK_ACCOUNT`, and `ROUTING_NUMBER` entity types used by
the demo, in addition to the allowed entity types above.

The policy's actor is the trusted client ID supplied by the server. Do not add
an actor input or accept actor/allowed recipients from the browser. To use a
different policy while testing, set `GUARD_POLICY_LABEL`; its default is
`email.sent`.

## Run

```sh
cp example.env .env.local
# Set ARCJET_KEY and OPENAI_API_KEY in .env.local
uv run --env-file .env.local fastapi dev --host 0.0.0.0
```

Open <http://localhost:8000>. The plain browser form intentionally has no custom
CSS or assets. Its trace shows the model fetching the client record, choosing
`send_email`, and receiving the aggregate conclusion, every denying rule, and
any detected sensitive-info entity types.

## Demo sequence

Run each scenario for either client:

- **Benign request** sends a PII-free acknowledgement to the client's own
  allowed address.
- **Wrong recipient** is denied only by membership for Client A, while the same
  recipient is allowed for Client B.
- **Sensitive information leak** uses the client's allowed address, isolating
  the sensitive-info control when the model echoes account details.
- **Layered defense** attempts an external recipient and account-data
  exfiltration. Membership and sensitive-info provide deterministic backstops;
  prompt-injection detection may add another denial reason.

Keep all rules in **LIVE** for this matrix. Review each decision in the Console
to show the trusted actor and per-rule evidence, then change and publish the
policy to demonstrate enforcement without an application deployment.
