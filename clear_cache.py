"""Run this to clear Python bytecode cache so updated files are used."""
import pathlib, shutil

project = pathlib.Path(__file__).parent
count = 0
for cache_dir in project.rglob("__pycache__"):
    shutil.rmtree(cache_dir, ignore_errors=True)
    print(f"Removed: {cache_dir}")
    count += 1
for pyc in project.rglob("*.pyc"):
    pyc.unlink(missing_ok=True)
    count += 1

print(f"\nCleared {count} cache entries. Now run: python app.py")
