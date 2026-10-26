"""Build the wheel without pip and check it ships everything the CLI needs at runtime:
the control catalog, the bundled examples, and the console script."""
import sys
import zipfile
from pathlib import Path

from setuptools import build_meta

dist = Path('dist')
dist.mkdir(exist_ok=True)
wheel = dist / build_meta.build_wheel(str(dist))
names = set(zipfile.ZipFile(wheel).namelist())
required = {
    'ai_gateway_audit/controls.yaml',
    'ai_gateway_audit/examples/insecure/config.yaml',
    'ai_gateway_audit/examples/insecure/docker-compose.yml',
    'ai_gateway_audit/examples/hardened/config.yaml',
    'ai_gateway_audit/examples/hardened/docker-compose.yml',
}
missing = sorted(required - names)
entry_points = next((n for n in names if n.endswith('.dist-info/entry_points.txt')), None)
script_ok = entry_points and 'ai-gateway-audit = ai_gateway_audit.__main__:main' in \
    zipfile.ZipFile(wheel).read(entry_points).decode()
print(f'{wheel.name}: {len(names)} files')
if missing or not script_ok:
    sys.exit(f'missing from wheel: {missing or ""} {"" if script_ok else "console script"}')
print('wheel contains the control catalog, examples and console script')
