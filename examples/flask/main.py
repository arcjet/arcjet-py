from flask import Flask, request, jsonify
import os
import logging

from arcjet import (
    arcjet_sync,
    shield,
    detect_bot,
    token_bucket,
    validate_email,
    is_spoofed_bot,
    Mode,
    BotCategory,
    EmailType,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

app = Flask(__name__)

aj = arcjet_sync(
    key=os.environ["ARCJET_KEY"],
    rules=[
        shield(mode=Mode.LIVE),
        detect_bot(
            mode=Mode.LIVE, allow=[BotCategory.SEARCH_ENGINE, "OPENAI_CRAWLER_SEARCH"]
        ),
        token_bucket(mode=Mode.LIVE, refill_rate=5, interval=10, capacity=10),
        validate_email(
            mode=Mode.LIVE,
            deny=[EmailType.DISPOSABLE, EmailType.INVALID, EmailType.NO_MX_RECORDS],
        ),
    ],
)


@app.route("/")
def hello():
    decision = aj.protect(request, requested=1, email="example@arcjet.com")
    if decision.is_denied():
        status = 429 if decision.reason.is_rate_limit() else 403
        return jsonify(error="Denied", reason=decision.reason.to_dict()), status

    if decision.ip.is_hosting():
        return jsonify(error="Hosting IP blocked"), 403

    if any(is_spoofed_bot(r) for r in decision.results):
        return jsonify(error="Spoofed bot"), 403

    return jsonify(message="Hello world", decision=decision.to_dict())


if __name__ == "__main__":
    app.run(debug=True)
