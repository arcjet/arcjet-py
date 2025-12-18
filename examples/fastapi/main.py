import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from arcjet import (
    arcjet,
    shield,
    detect_bot,
    token_bucket,
    Mode,
    BotCategory,
)

app = FastAPI()

aj = arcjet(
    key=os.environ["ARCJET_KEY"],  # Get your key from https://app.arcjet.com
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
                # BotCategory.MONITOR", // Uptime monitoring services
                # BotCategory.PREVIEW", // Link previews e.g. Slack, Discord
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
async def hello(request: Request):
    # Call protect() to evaluate the request against the rules
    decision = await aj.protect(
        request,
        requested=5,  # Deduct 5 tokens from the bucket
    )

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
