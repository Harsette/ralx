from pathlib import Path
import markdown
R=Path(__file__).resolve().parents[2]
body=markdown.markdown((R/'README.md').read_text(encoding='utf-8'),extensions=['fenced_code','tables','sane_lists'])
html='<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RalX README preview</title><link rel="stylesheet" href="/tmp/landing-proof/github-markdown.css"><style>body{margin:0;background:var(--bgColor-default,#fff)}.markdown-body{box-sizing:border-box;max-width:1012px;margin:40px auto;padding:40px;border:1px solid var(--borderColor-default,#d1d9e0);border-radius:6px}.markdown-body img{height:auto}.markdown-body pre{white-space:pre-wrap;overflow-wrap:anywhere}@media(prefers-color-scheme:dark){body{background:#0d1117}}@media(max-width:767px){.markdown-body{padding:18px;margin:0;border:0}}</style></head><body><article class="markdown-body">'+body+'</article></body></html>'
(R/'tmp/landing-proof/readme-preview.html').write_text(html,encoding='utf-8')
