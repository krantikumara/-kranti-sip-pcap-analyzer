"""
Run this on Windows: python fix_gradio_routes.py
Fixes gradio/routes.py where `template` variable is a dict instead of a string.
"""
import gradio.routes as r, inspect, pathlib, re

f   = pathlib.Path(inspect.getfile(r))
src = f.read_text(encoding="utf-8")

# Find more context around the TemplateResponse call
i = src.find("TemplateResponse(")
print("=== Context around TemplateResponse ===")
print(src[max(0,i-400):i+300])
print("=== End context ===\n")

# Find what `template` is assigned to
# Look for template = ... before the TemplateResponse call
snippet = src[max(0,i-600):i]
print("=== Looking for template assignment ===")
for line in snippet.split("\n")[-30:]:
    print(repr(line))
