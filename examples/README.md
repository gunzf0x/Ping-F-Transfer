# Practical Examples

Detailed usage examples for each `ping-f-transfer` subcommand, organized by language.

> **Tip:** Always use **absolute paths** with `-f` and **quote them** when they contain spaces or backslashes. This ensures the path is correctly embedded in the generated payload.

---

## Subcommands

| Guide | Description |
|---|---|
| [transfer.md](transfer.md) | Send a file directly from the current machine using `ping` |
| [generate.md](generate.md) | Generate base64-encoded oneliners for 8 scripting languages |
| [makefile.md](makefile.md) | Generate standalone script files for all 10 supported languages |

---

## At a Glance

```
ping-f-transfer <command> [flags]
```

| Command | Languages | Key use case |
|---|---|---|
| `transfer` | _(runs locally)_ | You have the tool installed on the sender machine |
| `generate` | Python, PowerShell, Bash, Perl, Ruby, PHP, Node.js | You have shell access but can't install the tool on the sender |
| `makefile` | All of the above + Go, C | You need a standalone file to transfer and execute on the sender |
