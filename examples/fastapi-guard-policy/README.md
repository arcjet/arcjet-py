# On behalf of the wrong client

This advanced FastAPI Guard policy demo uses a LangChain agent with two tools.
`get_client_messages` is an unguarded read tool that returns a support thread
containing an indirect prompt injection. `send_email` is wrapped with
`guard_tool`, so Arcjet evaluates the model-selected recipient and body before
the simulated email side effect can run.

The server owns the trusted mapping from the selected client to its actor ID,
support thread, and allowed recipients. The browser submits only `client`.

Client A does **not** allow `advisor-backup@gmail.com`; Client B does. Arcjet
checks the AI-generated action before sending is simulated.

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
   `allowed_recipients` (start in **DRY_RUN**).
2. **Prompt injection** on `incoming_message` (server execution, start in
   **DRY_RUN**).
3. **Sensitive info** on `body` (local SDK execution, start in **DRY_RUN**),
   allowing Email address, Given name, and Surname while denying every other
   detected entity type.

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
CSS or assets. Its trace shows the model reading the support thread, choosing
`send_email`, and receiving either the tool result or Arcjet's denial.

## Demo sequence

1. Keep all three rules in **DRY_RUN** and select **Client A**. The model reads
   the injected thread and autonomously calls `send_email` for
   `advisor-backup@gmail.com`. The email is simulated as sent while the
   would-have-blocked evidence is preserved.
2. Change all three rules to **LIVE** and repeat Client A. The aggregate is now
   `DENY`, so no simulated email is sent.
3. Review the decision in the Console to show the trusted `client-a` actor and
   evidence from each rule.
4. To isolate the actor-dependent rule, keep membership **LIVE**, return the two
   content rules to **DRY_RUN**, select **Client B**, and retry without changing
   the recipient or application. Its trusted list includes the address, so the
   simulated email is sent.
5. Tighten either content rule to **LIVE** and repeat. The app changes behavior
   without a deployment, and the evidence shows which live rule blocked it.
