import logging
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from arcjet import (
    BotCategory,
    Mode,
    SensitiveInfoEntityType,
    arcjet,
    detect_bot,
    detect_sensitive_info,
    shield,
    token_bucket,
)

app = FastAPI()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

arcjet_key = os.getenv("ARCJET_KEY")
if not arcjet_key:
    raise RuntimeError("ARCJET_KEY is required. Get one at https://app.arcjet.com")

aj = arcjet(
    key=arcjet_key,  # Get your key from https://app.arcjet.com
    rules=[
        # Shield protects your app from common attacks e.g. SQL injection
        shield(mode=Mode.LIVE),
        # Create a bot detection rule
        detect_bot(
            mode=Mode.LIVE,
            allow=[
                BotCategory.SEARCH_ENGINE,  # Google, Bing, etc
                # Uncomment to allow these other common bot categories
                # See the full list at https://arcjet.com/bot-list
                # BotCategory.MONITOR, # Uptime monitoring services
                # BotCategory.PREVIEW, # Link previews e.g. Slack, Discord
            ],
        ),
        # Detect and block PII in request content (emails, credit cards, etc.)
        detect_sensitive_info(
            mode=Mode.LIVE,
            deny=[
                SensitiveInfoEntityType.EMAIL,
                SensitiveInfoEntityType.CREDIT_CARD_NUMBER,
                SensitiveInfoEntityType.PHONE_NUMBER,
            ],
        ),
        # Create a token bucket rate limit. Other algorithms are supported
        token_bucket(
            # Tracked by IP address by default, but this can be customized
            # See https://docs.arcjet.com/fingerprints
            # characteristics: ["ip.src"],
            mode=Mode.LIVE,
            refill_rate=5,  # Refill 5 tokens per interval
            interval=10,  # Refill every 10 seconds
            capacity=10,  # Bucket capacity of 10 tokens
        ),
    ],
)


@app.get("/")
async def hello(request: Request, message: str = ""):
    # Call protect() to evaluate the request against the rules
    decision = await aj.protect(
        request,
        requested=5,  # Deduct 5 tokens from the bucket
        sensitive_info_value=message,  # Scan the message query param for PII
    )

    # Typed IP details are available directly on decision.ip_details
    ip = decision.ip_details
    if ip and ip.city and ip.country_name:
        logger.info("Request from %s, %s", ip.city, ip.country_name)

    # Handle denied requests
    if decision.is_denied():
        status = 429 if decision.reason.is_rate_limit() else 403
        return JSONResponse(
            {"error": "Denied", "reason": decision.reason.to_dict()},
            status_code=status,
        )

    # Check IP metadata (VPNs, hosting, geolocation, etc)
    if decision.ip.is_hosting():
        # Requests from hosting IPs are likely from bots, so they can usually be
        # blocked. However, consider your use case - if this is an API endpoint
        # then hosting IPs might be legitimate.
        # https://docs.arcjet.com/blueprints/vpn-proxy-detection

        return JSONResponse(
            {"error": "Denied from hosting IP"},
            status_code=403,
        )

    return {"message": "Hello world", "decision": decision.to_dict()}
