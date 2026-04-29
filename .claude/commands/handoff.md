---
description: Hand off to fresh session, work continues from hook
allowed-tools: Bash(gt handoff:*)
argument-hint: [message]
---

Hand off to a fresh session.

User's handoff message (if any): $ARGUMENTS

Execute these steps in order:

1. Ask the user: "Ready to hand off? This will restart the session. (y/N)"
   - If the user says no or doesn't confirm, stop here. Do NOT run gt handoff.
   - Only proceed if the user explicitly confirms with 'y' or 'yes'.

2. If user provided a message, run the handoff command with a subject and message:
   `gt handoff -y -s "HANDOFF: Session cycling" -m "USER_MESSAGE_HERE"`

3. If no message was provided, run the handoff command:
   `gt handoff -y`

Note: The new session will auto-prime via the SessionStart hook and find your handoff mail.
End watch. A new session takes over, picking up any molecule on the hook.
