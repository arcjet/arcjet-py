from __future__ import annotations

import os

from arcjet_sensitive_info_rampart import rampart
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from arcjet.guard import launch_arcjet, local_input, server_input

key = os.getenv("ARCJET_KEY")
if not key:
    raise RuntimeError("ARCJET_KEY is required")

app = FastAPI()
guard = launch_arcjet(
    key=key,
    base_url=os.getenv("ARCJET_BASE_URL", "https://decide.arcjet.com"),
    sensitive_info_backend=rampart(),
)

PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Arcjet Guard policy example</title>
</head>
<body>
  <main>
    <h1>Send an email</h1>
    <p>The <code>email</code> policy allows only configured recipients. The body is evaluated locally and its raw value is never sent to Arcjet.</p>
    <form id="form">
      <p><label>Recipient<br>
        <small>Try <code>arcjet.com</code> for an allowed value.</small>
        <br><input name="to" value="arcjet.com" required>
      </label></p>
      <p><label>Body<br>
        <small>Try adding a credit card number to exercise local sensitive-info detection.</small>
        <br><textarea name="body" rows="6" cols="60" required>Hello from the Python SDK.</textarea>
      </label></p>
      <button>Evaluate policy</button>
    </form>
    <section id="result" aria-live="polite" hidden></section>
  </main>
  <script>
    const form = document.querySelector('#form');
    const result = document.querySelector('#result');
    function showResult(conclusion, message) {
      const heading = document.createElement('h2');
      const description = document.createElement('p');
      heading.textContent = conclusion;
      description.textContent = message;
      result.replaceChildren(heading, description);
      result.hidden = false;
    }
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = form.querySelector('button');
      button.disabled = true;
      button.textContent = 'Evaluating…';
      try {
        const fields = new FormData(form);
        const response = await fetch('/evaluate', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ to: fields.get('to'), body: fields.get('body') }),
        });
        const data = await response.json();
        showResult(
          data.conclusion || 'Error',
          data.message || data.reason || 'The policy could not be evaluated.',
        );
      } catch (error) {
        showResult('Error', error instanceof Error ? error.message : 'Unknown error');
      } finally {
        button.disabled = false;
        button.textContent = 'Evaluate policy';
      }
    });
  </script>
</body>
</html>"""


class Email(BaseModel):
    to: str
    body: str


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return PAGE


@app.post("/evaluate")
async def evaluate(email: Email) -> dict[str, object]:
    decision = await guard.guard(
        label="email",
        inputs={
            "to": server_input.string(email.to),
            "body": local_input.string(email.body),
        },
    )
    message = (
        "The email is allowed by the active policy."
        if decision.conclusion == "ALLOW"
        else "The email was blocked by the active policy."
    )
    return {
        "conclusion": decision.conclusion,
        "reason": decision.reason,
        "message": message,
        "policy_status": (
            decision.policy_evaluation.status if decision.policy_evaluation else None
        ),
        "results": [
            {
                "execution": result.execution,
                "type": result.result.type,
                "conclusion": result.result.conclusion,
            }
            for result in decision.policy_results
        ],
    }
