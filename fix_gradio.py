"""
fix_gradio.py - Fixes gradio/routes.py TemplateResponse argument order.
Run once: python fix_gradio.py
"""
import gradio.routes as r
import inspect
import pathlib

f   = pathlib.Path(inspect.getfile(r))
src = f.read_text(encoding="utf-8")

print("Gradio routes file:", f)
print()

# Count all TemplateResponse calls to fix
fixed = 0
lines = src.split("\n")
new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    # Find lines with TemplateResponse( followed by a string template name
    if "templates.TemplateResponse(" in line and i + 3 < len(lines):
        # Check if next line is the template string (old-style call)
        next1 = lines[i+1].strip()
        next2 = lines[i+2].strip() if i+2 < len(lines) else ""
        next3 = lines[i+3].strip() if i+3 < len(lines) else ""

        # Old style: TemplateResponse(\n  template,\n  {"request": ...},\n)
        if (next1.startswith('"') or next1 == "template,") and "request" in next2:
            indent = len(line) - len(line.lstrip())
            sp = " " * indent

            # Extract template name from next1
            tname = next1.rstrip(",")

            # Extract context - find the dict content
            ctx_line = next2  # {"request": request, "config": config},
            # Remove "request" from context since it becomes a named arg
            ctx_content = ctx_line.strip().rstrip(",")
            # Replace {"request": request, "config": config} with {"config": config}
            import re
            ctx_clean = re.sub(r'"request":\s*request,?\s*', "", ctx_content).strip()
            ctx_clean = ctx_clean.replace("{, ", "{").replace("{,", "{")
            if ctx_clean == "{}":
                ctx_clean = "None"

            # Check for closing paren
            close_line = next3

            new_lines.append(sp + "return templates.TemplateResponse(")
            new_lines.append(sp + "    request=request,")
            new_lines.append(sp + "    name=" + tname + ",")
            if ctx_clean != "None":
                new_lines.append(sp + "    context=" + ctx_clean.rstrip(",") + ",")
            new_lines.append(sp + ")")
            print(f"  Fixed TemplateResponse at line {i+1}")
            fixed += 1
            # Skip the original lines
            i += 4
            # Skip any extra closing paren line if needed
            if i < len(lines) and lines[i].strip() == ")":
                i += 1
            continue

    new_lines.append(line)
    i += 1

if fixed > 0:
    new_src = "\n".join(new_lines)
    # Clear pyc cache
    cache_dir = f.parent / "__pycache__"
    for pyc in cache_dir.glob("routes*.pyc"):
        pyc.unlink(missing_ok=True)
        print(f"  Deleted: {pyc.name}")
    f.write_text(new_src, encoding="utf-8")
    print(f"\nFixed {fixed} TemplateResponse call(s) in gradio/routes.py")
    print("Now run: python app.py")
else:
    print("No old-style TemplateResponse calls found.")
    print("Showing all TemplateResponse calls:")
    for j, ln in enumerate(lines):
        if "TemplateResponse" in ln:
            print(f"  Line {j+1}: {ln}")
            # Show context
            for k in range(j+1, min(j+6, len(lines))):
                print(f"  Line {k+1}: {lines[k]}")
            print()
