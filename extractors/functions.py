def extract_functions(r2):
    """
    Compatible with radare2 5.9.8 and 6.0.9
    """

    funcs = r2.cmdj("aflj") or []
    results = []

    for f in funcs:
        offset = f.get("offset")
        name = f.get("name", "unknown")

        # Always keep function entry
        entry = {
            "name": name,
            "offset": offset,
            "called_symbols": [],
            "string_refs": [],
            "syscalls": []
        }

        if not isinstance(offset, int):
            results.append(entry)
            continue

        disasm = r2.cmdj(f"pdfj @ {offset}")
        if not disasm or not isinstance(disasm.get("ops"), list):
            results.append(entry)
            continue

        called_symbols = set()
        string_refs = set()
        syscalls = set()

        for op in disasm["ops"]:
            disasm_text = (op.get("disasm") or "").lower()
            opcode = (op.get("opcode") or "").lower()
            op_type = (op.get("type") or "").lower()

            # -----------------------------
            # FUNCTION CALL DETECTION
            # -----------------------------
            # r2 5.x: call appears in disasm
            # r2 6.x: jump field is reliable
            if "call" in disasm_text or op_type == "call":
                # Prefer resolved symbol
                if "sym." in disasm_text:
                    called_symbols.add(disasm_text.strip())
                else:
                    jump = op.get("jump")
                    if isinstance(jump, int):
                        called_symbols.add(hex(jump))

            # -----------------------------
            # STRING REFERENCES
            # -----------------------------
            # 5.9.8 → refptr
            # 6.0.9 → refptr or ptr
            ref = op.get("refptr") or op.get("ptr")
            if ref is not None:
                string_refs.add(str(ref))

            # -----------------------------
            # SYSCALLS
            # -----------------------------
            # 5.x → type == syscall
            # 6.x → opcode contains syscall
            if op_type == "syscall" or "syscall" in opcode:
                syscalls.add(op.get("disasm", "").strip())

        entry["called_symbols"] = sorted(called_symbols)
        entry["string_refs"] = sorted(string_refs)
        entry["syscalls"] = sorted(syscalls)

        results.append(entry)

    return results
