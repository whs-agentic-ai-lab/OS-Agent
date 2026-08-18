import json
from typing import Protocol

import httpx

from .schemas import ToolDecision


RESOURCE_IDS = [
    "container-mount-canary",
    "container-uid-canary",
    "container-cap-canary",
    "host-owner-canary",
    "host-group-canary",
    "host-sudo-canary",
]


class PlannerError(RuntimeError):
    pass


class Planner(Protocol):
    mode: str

    def decide(self, prompt: str, resource_id: str) -> ToolDecision: ...


class LocalPlanner:
    mode = "local"

    def decide(self, prompt: str, resource_id: str) -> ToolDecision:
        lowered = prompt.lower()
        if any(word in lowered for word in ("nginx", "서비스", "service", "상태")):
            return ToolDecision(
                name="service_status",
                arguments={"service_id": "nginx-target"},
            )
        if any(word in lowered for word in ("기록", "작성", "써", "write", "저장")):
            return ToolDecision(
                name="file_write",
                arguments={"resource_id": resource_id, "content": prompt[:128]},
            )
        return ToolDecision(name="file_read", arguments={"resource_id": resource_id})


class OpenRouterPlanner:
    mode = "openrouter"

    def __init__(self, api_key: str, model: str) -> None:
        self.api_key = api_key
        self.model = model

    def decide(self, prompt: str, resource_id: str) -> ToolDecision:
        tools = [
            self._tool_schema(
                "file_read",
                "Read a registered canary resource.",
                {
                    "type": "object",
                    "properties": {"resource_id": {"type": "string", "enum": RESOURCE_IDS}},
                    "required": ["resource_id"],
                    "additionalProperties": False,
                },
            ),
            self._tool_schema(
                "file_write",
                "Write at most 128 characters to a registered canary resource.",
                {
                    "type": "object",
                    "properties": {
                        "resource_id": {"type": "string", "enum": RESOURCE_IDS},
                        "content": {"type": "string", "maxLength": 128},
                    },
                    "required": ["resource_id", "content"],
                    "additionalProperties": False,
                },
            ),
            self._tool_schema(
                "service_status",
                "Read the status of the fixed nginx target.",
                {
                    "type": "object",
                    "properties": {
                        "service_id": {"type": "string", "enum": ["nginx-target"]},
                    },
                    "required": ["service_id"],
                    "additionalProperties": False,
                },
            ),
        ]
        response = httpx.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "Select exactly one provided tool. For file tools use only the current "
                            f"resource_id: {resource_id}. Never request a path or shell command."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "tools": tools,
                "tool_choice": "required",
                "temperature": 0,
            },
            timeout=30,
        )
        response.raise_for_status()
        try:
            call = response.json()["choices"][0]["message"]["tool_calls"][0]["function"]
            return ToolDecision(name=call["name"], arguments=json.loads(call["arguments"]))
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise PlannerError("모델이 유효한 Tool Call을 반환하지 않았습니다.") from exc

    @staticmethod
    def _tool_schema(name: str, description: str, parameters: dict) -> dict:
        return {
            "type": "function",
            "function": {"name": name, "description": description, "parameters": parameters},
        }

