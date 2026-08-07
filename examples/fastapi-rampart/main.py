import logging
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from arcjet import Mode, arcjet, detect_sensitive_info, shield

# The Rampart backend ships in the optional `arcjet[sensitive-info-rampart]`
# extra. Install it with: pip install "arcjet[sensitive-info-rampart]"
from arcjet_sensitive_info_rampart import rampart

app = FastAPI()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

arcjet_key = os.getenv("ARCJET_KEY")
if not arcjet_key:
    raise RuntimeError(
        "ARCJET_KEY is required. Get one with: arcjet sites get-key"
        " or from https://app.arcjet.com"
    )

aj = arcjet(
    key=arcjet_key,  # Get your key with: arcjet sites get-key
    rules=[
        # Shield protects your app from common attacks e.g. SQL injection
        shield(mode=Mode.LIVE),
        # Detect and block sensitive information using the on-device Rampart NER
        # model. This detects names, addresses, and government/financial
        # identifiers in addition to the four types the default engine detects —
        # all locally, so no data leaves your environment. The model loads on
        # the first request, then is reused.
        detect_sensitive_info(
            mode=Mode.LIVE,
            deny=[
                "EMAIL",
                "PHONE_NUMBER",
                "CREDIT_CARD_NUMBER",
                "SSN",
                "GIVEN_NAME",
                "SURNAME",
                "STREET_NAME",
            ],
            backend=rampart(),
        ),
    ],
)


@app.get("/")
async def hello(request: Request, message: str = ""):
    # Call protect() to scan the message for sensitive information.
    decision = await aj.protect(
        request,
        sensitive_info_value=message,  # Scan the message query param for PII
    )

    if decision.is_denied():
        return JSONResponse(
            {"error": "Denied", "reason": decision.reason.to_dict()},
            status_code=403,
        )

    return {"message": "Hello world", "decision": decision.to_dict()}
