from pathlib import Path
p = Path('internal/transport/inbound.go')
s = p.read_text(encoding='utf-8')
for i,l in enumerate(s.splitlines(), start=1):
    print(f"{i}: {l}")
