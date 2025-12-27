from __future__ import annotations

from dataclasses import dataclass

from backend.messages import MessageSegment


@dataclass
class PolicyDecision:
    action: str  # "allow" | "block" | "rewrite" | "downgrade_tools"
    reason: str
    rewritten_user_prompt: str | None = None
    allowed_tool_names: list[str] | None = None


class PolicyEngine:
    """
    Baseline defender v0:
    - Static policy + denylist heuristics
    - Deterministic
    """

    SUSPICIOUS_SUBSTRINGS = [
        "ignore previous",
        "ignore all previous",
        "disregard previous",
        "override",
        "developer message",
        "developer mode",
        "system prompt",
        "reveal the system prompt",
        "show the system prompt",
        "begin_system",
        "end_system",
        "you are now system",
        "act as system",
        "role: system",
        "forget the above",
        "jailbreak",
    ]

    ROLE_REDEF_PATTERNS = [
        "you are now",
        "from now on",
        "act as",
        "pretend to be",
        "simulate",
        "roleplay",
        "as the system",
        "as system",
        "as the developer",
    ]

    def evaluate(
        self,
        system_prompt: str,
        segments: list[MessageSegment],
        user_prompt: str,
        tool_names: list[str],
    ) -> PolicyDecision:
        """
        Scan ALL untrusted content (user, retrieved_doc, tool_output).
        System content is excluded by construction.
        """

        # Collect untrusted text only
        untrusted_texts: list[str] = []
        for s in segments:
            if s.source != "system":
                untrusted_texts.append(s.content or "")

        combined = "\n".join(untrusted_texts).lower()

        # 1) Hard block: explicit system prompt extraction
        if "system prompt" in combined or "begin_system" in combined:
            return PolicyDecision(
                action="block",
                reason="Detected attempt to reveal or reference system prompt.",
            )

        # 2) Injection / role redefinition
        suspicious = any(sub in combined for sub in self.SUSPICIOUS_SUBSTRINGS)
        role_redef = any(pat in combined for pat in self.ROLE_REDEF_PATTERNS)

        if suspicious or role_redef:
            # Remove dangerous tools (v0 = post_message only)
            allowed_tools = [t for t in tool_names if t != "post_message"]

            rewritten = self._rewrite_prompt(user_prompt)

            if rewritten != user_prompt:
                return PolicyDecision(
                    action="rewrite",
                    reason="Detected injection-like text; rewrote prompt.",
                    rewritten_user_prompt=rewritten,
                    allowed_tool_names=allowed_tools,
                )

            return PolicyDecision(
                action="downgrade_tools",
                reason="Detected injection-like text; removed risky tools.",
                allowed_tool_names=allowed_tools,
            )

        return PolicyDecision(
            action="allow",
            reason="No injection heuristics triggered.",
        )

    def _rewrite_prompt(self, prompt: str) -> str:
        """
        Remove lines containing suspicious substrings.
        """
        if not prompt:
            return prompt

        out: list[str] = []
        for line in prompt.splitlines():
            low = line.lower()
            if any(sub in low for sub in self.SUSPICIOUS_SUBSTRINGS):
                continue
            out.append(line)

        rewritten = "\n".join(out).strip()
        return rewritten if rewritten else prompt
