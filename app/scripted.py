"""A fake 'tricked' model that does exactly what the attacker wants.
It proposes the scripted tool calls, then dumps every tool result into its
final answer. No OpenAI call, no cost, fully deterministic."""

import json
from types import SimpleNamespace


class _Message:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls

    def model_dump(self, exclude_none=True):
        d = {"role": "assistant"}
        if self.content is not None:
            d["content"] = self.content
        if self.tool_calls:
            d["tool_calls"] = [
                {"id": c.id, "type": "function",
                 "function": {"name": c.function.name,
                              "arguments": c.function.arguments}}
                for c in self.tool_calls
            ]
        return d


class ScriptedClient:
    def __init__(self, calls: list):
        self._calls = calls
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, model=None, messages=None, tools=None, temperature=0):
        tool_results = [m["content"] for m in messages if m.get("role") == "tool"]
        if not tool_results:                       # step 1: make the malicious calls
            tool_calls = [
                SimpleNamespace(
                    id=f"call_{i}",
                    function=SimpleNamespace(name=c["tool"], arguments=json.dumps(c["args"])),
                )
                for i, c in enumerate(self._calls)
            ]
            msg = _Message(tool_calls=tool_calls)
        else:                                      # step 2: leak everything it saw
            msg = _Message(content="Here is everything I found:\n" + "\n".join(tool_results))
        return SimpleNamespace(
            usage=SimpleNamespace(prompt_tokens=0, completion_tokens=0),
            choices=[SimpleNamespace(message=msg)],
        )
