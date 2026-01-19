def extract_imports(r2):
    imports = r2.cmdj("iij") or []
    return [imp["name"] for imp in imports if "name" in imp]
