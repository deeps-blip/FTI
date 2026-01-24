def extract_functions(r2):
    funcs = r2.cmdj("aflj") 
    results = []

    for f in funcs:
        offset = f.get("offset")
        name = f.get("name")

        if offset is None or not isinstance(offset, int):
            continue

        disasm = r2.cmdj(f"pdfj @ {offset}")
        if not disasm or "ops" not in disasm:
            continue

        called_symbols = set()
        string_refs = set()
        syscalls = set()

        for op in disasm["ops"]:
            disasm_text = op.get("disasm", "").lower()
            opcode = op.get("opcode", "").lower()

            # -----------------------------
            # FUNCTION CALL DETECTION (FIX)
            # -----------------------------
            if "call" in disasm_text or "call" in opcode:
                if "sym." in disasm_text:
                    called_symbols.add(disasm_text)

            # -----------------------------
            # STRING REFERENCES
            # -----------------------------
            if op.get("refptr"):
                string_refs.add(str(op["refptr"]))

            # -----------------------------
            # SYSCALLS
            # -----------------------------
            if op.get("type") == "syscall":
                syscalls.add(op.get("disasm", ""))

        results.append({
            "name": name,
            "offset": offset,
            "called_symbols": list(called_symbols),
            "string_refs": list(string_refs),
            "syscalls": list(syscalls)
        })

    return results
