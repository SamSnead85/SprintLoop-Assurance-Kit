# MCP client examples

These examples connect an AI engineering client to the local read-only SprintLoop Assurance stdio server.

1. Copy `server-config.example.json` outside the Git candidate.
2. Replace each `/srv/sprintloop-assurance/...` path with a narrow existing absolute directory.
3. Keep bundle, receiver, and dossier roots pairwise separate.
4. Clone the source to `/absolute/pinned/SprintLoop-Assurance-Kit`, review it, and detach at `35febce58e85ceec126ee6ce940461a25cfbe93e`; no npm package is published.
5. Add the server using `codex-command.txt`, `claude-code.mcp.json`, or `cursor.mcp.json`.
6. Review the six read-only tools shown by the client.

No example contains a credential, private key, remote endpoint, or write-capable tool. See the full [MCP integration guide](../../docs/MCP.md).
