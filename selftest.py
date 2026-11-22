#!/usr/bin/env python3
import py_compile, subprocess, sys
py_compile.compile("kl_multi_parallel.py", doraise=True)
assert "Kontenlaris.Studio" in open("kl_multi_parallel.py").read()
r = subprocess.run([sys.executable, "kl_multi_parallel.py", "--help"], capture_output=True)
assert r.returncode == 0
g = subprocess.run([sys.executable, "kl_multi_parallel.py", "--targets", "127.0.0.1"], capture_output=True)
assert g.returncode == 2, "guard --yes harus exit 2"
print("selftest: OK (compile, help, credit, guard --yes)")
