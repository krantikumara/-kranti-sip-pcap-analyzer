"""
setup_env.py - Run this ONCE to fix all environment issues.
Usage: python setup_env.py
"""
import subprocess
import sys
import pathlib
import inspect
import re

print("=" * 60)
print("  Kranti PCAP Analyzer - Environment Setup")
print("=" * 60)

# ── Step 1: Fix numpy ─────────────────────────────────────────────────────────
print("\n[1/4] Fixing numpy + numexpr + bottleneck...")
subprocess.run([sys.executable, "-m", "pip", "install",
    "numpy<2", "numexpr", "bottleneck", "--quiet"], check=False)
print("  Done")

# ── Step 2: Fix jinja2/environment.py ────────────────────────────────────────
print("\n[2/4] Patching jinja2/environment.py...")
try:
    import jinja2.environment as je
    filepath = pathlib.Path(inspect.getfile(je))
    src = filepath.read_text(encoding="utf-8")
    
    # Show the exact _load_template function to know what we're patching
    i = src.find("def _load_template")
    snippet = src[i:i+500] if i != -1 else "NOT FOUND"
    print("  Found _load_template:")
    for line in snippet.split("\n")[:15]:
        print("    " + line)
    
    # The cache_key line - could be any of these forms
    patched = False
    patterns = [
        # Form 1: cache_key = (weakref.ref(self), name, globals)
        (r'cache_key\s*=\s*\(([^)]*),\s*globals\s*\)',
         lambda m: f'cache_key = ({m.group(1)})'),
        # Form 2: cache_key = (weakref.ref(self), name, raw_globals)  
        (r'cache_key\s*=\s*\(([^)]*),\s*raw_globals\s*\)',
         lambda m: f'cache_key = ({m.group(1)})'),
    ]
    
    new_src = src
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, new_src)
        if result != new_src:
            new_src = result
            patched = True
            print(f"  Applied pattern: {pattern}")
    
    if patched:
        # Clear pyc cache
        cache_dir = filepath.parent / "__pycache__"
        for pyc in cache_dir.glob("environment*.pyc"):
            pyc.unlink(missing_ok=True)
            print(f"  Deleted cache: {pyc.name}")
        filepath.write_text(new_src, encoding="utf-8")
        print("  jinja2/environment.py PATCHED OK")
    else:
        # Try direct string replacements as fallback
        lines = src.split("\n")
        new_lines = []
        fixed = False
        for line in lines:
            if "cache_key" in line and "globals" in line and "=" in line:
                print(f"  Found cache_key line: {line.strip()}")
                # Remove globals from the tuple
                new_line = re.sub(r',\s*globals\b', '', line)
                new_line = re.sub(r',\s*raw_globals\b', '', new_line)
                if new_line != line:
                    print(f"  Fixed to:            {new_line.strip()}")
                    new_lines.append(new_line)
                    fixed = True
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        
        if fixed:
            for pyc in (filepath.parent / "__pycache__").glob("environment*.pyc"):
                pyc.unlink(missing_ok=True)
            filepath.write_text("\n".join(new_lines), encoding="utf-8")
            print("  jinja2/environment.py PATCHED OK (line-by-line method)")
        else:
            print("  WARNING: Could not find cache_key line to patch!")
            print("  Showing full _load_template:")
            print(snippet)

except Exception as e:
    print(f"  ERROR: {e}")
    import traceback
    traceback.print_exc()

# ── Step 3: Fix gradio_client/utils.py ───────────────────────────────────────
print("\n[3/4] Patching gradio_client/utils.py...")
try:
    import gradio_client.utils as gu
    filepath2 = pathlib.Path(inspect.getfile(gu))
    src2 = filepath2.read_text(encoding="utf-8")
    
    old = "def _json_schema_to_python_type(schema, defs=None):\n"
    new = "def _json_schema_to_python_type(schema, defs=None):\n    if not isinstance(schema, dict): return \"Any\"\n"
    
    old2 = "        raise APIInfoParseError(f\"Cannot parse schema {schema}\")"
    new2 = "        return \"Any\"  # patched"
    
    changed = False
    if old in src2 and new not in src2:
        src2 = src2.replace(old, new)
        changed = True
        print("  Fixed: _json_schema_to_python_type guard")
    if old2 in src2 and new2 not in src2:
        src2 = src2.replace(old2, new2)
        changed = True
        print("  Fixed: APIInfoParseError -> return Any")
    
    if changed:
        for pyc in (filepath2.parent / "__pycache__").glob("utils*.pyc"):
            pyc.unlink(missing_ok=True)
        filepath2.write_text(src2, encoding="utf-8")
        print("  gradio_client/utils.py PATCHED OK")
    else:
        print("  Already patched or not needed")

except Exception as e:
    print(f"  ERROR: {e}")

# ── Step 4: Verify ────────────────────────────────────────────────────────────
print("\n[4/4] Verifying...")
try:
    import gradio as gr
    print(f"  gradio {gr.__version__} imports OK")
except Exception as e:
    print(f"  gradio import failed: {e}")

print("\n" + "=" * 60)
print("  Setup complete! Now run: python app.py")
print("=" * 60)
