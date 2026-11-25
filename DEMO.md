# CYBOT demo

Record the screen with no voice. Leave each caption up while you do the step. The server is started with `CYBOT_DEMO=1`, so the example.com run is a local fixture and does not contact the public internet.

| Time | Do this | Caption |
| --- | --- | --- |
| 0:00 | Title card, CYBOT wordmark | CYBOT. Scope first, then recon. |
| 0:08 | Create or enter the dashboard password | The dashboard password is a hash. Connector keys stay in Fly.io. |
| 0:18 | Open Settings | OpenCode is the primary provider. Gemini is the active Sprites connector when it is granted. |
| 0:28 | Test a connector, then return the provider to OpenCode | A connector test is a small gateway call. Ollama Cloud is optional. |
| 0:40 | Mission. Target `payments.example.net`. Check scope | Out of scope. |
| 0:48 | Hold on the red result | Refused. The attempt is in the authorization log. |
| 0:56 | Load example.com demo | Fixture only. No packets to example.com. |
| 1:06 | Start recon | Light checks, and only on names the scope allows. |
| 1:16 | Live log | In-scope names stay. mail.example.com and anything else are refused. |
| 1:28 | Findings | Notes that share a type are grouped, with a host count. |
| 1:40 | Explain | One short paragraph. No attack steps. |
| 1:52 | Report. Show the status, provider, Markdown, and PDF | The report says these are not confirmed vulnerabilities. |
| 2:02 | Tools | What is integrated, what is optional, and what was rejected. |
| 2:12 | End card | Runs on a Fly.io Sprite. |

Do not type a real program's assets unless you are authorized to test them. The demo fixture is enough.
