import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from arcjet import (
    arcjet,
    shield,
    token_bucket,
    Mode,
)

app = FastAPI()

aj = arcjet(
    key=os.environ["ARCJET_KEY"],
    rules=[
        shield(mode=Mode.LIVE),
        token_bucket(
            mode=Mode.LIVE,
            refill_rate=5,
            interval=10,
            capacity=10,
            characteristics=["userId"],
        ),
    ],
)


@app.get("/")
async def hello(request: Request):
    decision = await aj.protect(
        request, requested=1, characteristics={"userId": "user-1234"}
    )

    if decision.is_denied():
        status = 429 if decision.reason.is_rate_limit() else 403
        return JSONResponse(
            {"error": "Denied", "reason": decision.reason.to_dict()},
            status_code=status,
        )

    return {"message": "Hello world", "decision": decision.to_dict()}
