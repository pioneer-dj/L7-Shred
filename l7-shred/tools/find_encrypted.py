from pathlib import Path
p = Path('internal/transport/inbound.go')
s = p.read_bytes()
lines = s.splitlines()
for i,l in enumerate(lines, start=1):
    if b'encrypted' in l:
        print(i, l)
