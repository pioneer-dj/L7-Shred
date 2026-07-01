from pathlib import Path
p = Path('internal/transport/inbound.go')
s = p.read_bytes()
lines = s.splitlines()
for idx in range(170, 190):
    if idx < len(lines):
        print(f"{idx+1}: {lines[idx]!r}")
    else:
        print(f"{idx+1}: <no line>")
