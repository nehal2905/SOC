# Architecture Assets

## Diagrams

| File | Description |
|------|-------------|
| `lab-topology.mmd` | Mermaid source — network + data flow |
| `lab-topology.png` | Export target for README (generate below) |
| `attack-detect-respond-workflow.md` | Sequence + per-stage workflow |

## Generate `lab-topology.png`

**Option A — Mermaid Live**

1. Open https://mermaid.live
2. Paste contents of `lab-topology.mmd`
3. Export PNG → save as `lab-topology.png`

**Option B — CLI**

```bash
npm install -g @mermaid-js/mermaid-cli
mmdc -i lab-topology.mmd -o lab-topology.png -b transparent
```

**Option C — VS Code**

Install "Markdown Preview Mermaid Support" → preview `lab-topology.mmd` → export from preview if supported.

Place the PNG in this folder so `README.md` renders:

```markdown
![Lab topology](architecture/lab-topology.png)
```
