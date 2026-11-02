"""Generate an AppCache manifest from one consistent repository snapshot."""
from pathlib import Path
import hashlib
import re

root = Path(__file__).resolve().parents[2]
base = root / "raw13"
files = sorted(p for p in base.rglob("*") if p.is_file()
               and p.suffix in {".js", ".html", ".bin"})
urls = {"offline.html", "jb.html?log=1"}
digest = hashlib.sha256()
for path in files:
    name = path.relative_to(base).as_posix()
    content = path.read_bytes()
    if path.suffix == ".js" and content.lstrip().startswith(b"<"):
        raise SystemExit("Refusing to cache HTML disguised as JavaScript: " + name)
    digest.update(name.encode() + b"\0" + content + b"\0")
    urls.add(name)
    if path.suffix in {".js", ".html"}:
        text = content.decode("utf-8")
        for match in re.finditer(r"""["'](\./)?([A-Za-z0-9_./-]+\.js\?[^"'\s]+)["']""", text):
            target = match.group(2)
            local = path.parent / target.split("?")[0]
            if not local.is_file():
                raise SystemExit("Missing dependency: " + str(local))
            urls.add(local.relative_to(base).as_posix() + "?" + target.split("?", 1)[1])
launcher = (base / "offline.html").read_bytes()
digest.update(launcher)
manifest = "CACHE MANIFEST\n# snapshot: " + digest.hexdigest() + "\n\nCACHE:\n"
manifest += "\n".join(sorted(urls)) + "\n\nNETWORK:\n*\n"
(base / "cache.appcache").write_text(manifest, encoding="utf-8", newline="\n")
print("Prepared offline snapshot:", digest.hexdigest(), "resources:", len(urls))
