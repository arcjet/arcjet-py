import logging
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from arcjet import (
    Mode,
    arcjet,
    detect_bot,
    shield,
    token_bucket,
)

app = FastAPI()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

arcjet_key = os.getenv("ARCJET_KEY")
if not arcjet_key:
    raise RuntimeError(
        "ARCJET_KEY is required. Get one at https://app.arcjet.com")

openai_api_key = os.getenv("OPENAI_API_KEY")
if not openai_api_key:
    raise RuntimeError(
        "OPENAI_API_KEY is required. Get one at https://platform.openai.com"
    )

llm = ChatOpenAI(model="gpt-4o-mini", api_key=openai_api_key)

prompt = ChatPromptTemplate.from_messages(
    [
        ("system", "You are a helpful assistant."),
        ("human", "{message}"),
    ]
)

chain = prompt | llm | StrOutputParser()


class ChatRequest(BaseModel):
    message: str


aj = arcjet(
    key=arcjet_key,  # Get your key from https://app.arcjet.com
    rules=[
        # Shield protects your app from common attacks e.g. SQL injection
        shield(mode=Mode.LIVE),
        # Create a bot detection rule
        detect_bot(
            mode=Mode.LIVE,
            # An empty allow list blocks all bots, which is a good default for
            # an AI chat app.
            allow=[
                "CURL",  # Allow curl so we can test it (see README)
                # Uncomment to allow these other common bot categories
                # See the full list at https://arcjet.com/bot-list
                # BotCategory.MONITOR, # Uptime monitoring services
                # BotCategory.PREVIEW, # Link previews e.g. Slack, Discord
            ],
        ),
        # Create a token bucket rate limit. Other algorithms are supported
        token_bucket(
            # Track budgets by arbitrary characteristics of the request. Here
            # we use user ID, but you could pass any value. Removing this will
            # fall back to IP-based rate limiting.
            characteristics=["userId"],
            mode=Mode.LIVE,
            refill_rate=5,  # Refill 5 tokens per interval
            interval=10,  # Refill every 10 seconds
            capacity=10,  # Bucket capacity of 10 tokens
        ),
    ],
)


@app.post("/chat")
async def chat(request: Request, body: ChatRequest):
    # Replace with actual user ID from the user session
    userId = "your_user_id"

    # Call protect() to evaluate the request against the rules
    decision = await aj.protect(
        request,
        # Deduct 5 tokens from the bucket
        requested=5,
        # Identify the user for rate limiting purposes
        characteristics={"userId": userId},
    )

    # Handle denied requests
    if decision.is_denied():
        status = 429 if decision.reason.is_rate_limit() else 403
        return JSONResponse(
            {"error": "Denied", "reason": decision.reason.to_dict()},
            status_code=status,
        )

    # All rules passed, proceed with handling the request
    reply = await chain.ainvoke({"message": body.message})

    return {"reply": reply}
