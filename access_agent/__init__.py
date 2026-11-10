# access_agent — پل دسترسی مستقل عامل هوشمند به سرور (مستقل از پرستو)
"""Access Agent: an independent, always-on server bridge for the AI agent.

Design goals (owner decision 2026-11-05):
- Fully independent of Parastoo (and of Docker) — pure Python stdlib + systemd.
- Survives Parastoo crashes; used for testing, repairs and reinstalling Parastoo.
- Custodian of the owner's GitHub PAT; issues session-scoped tokens to the agent.
"""

VERSION = "0.6.3"
SERVICE_NAME = "access-agent"
