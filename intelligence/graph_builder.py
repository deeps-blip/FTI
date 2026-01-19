def build_call_graph(functions):
    edges = set()

    for f in functions:
        src = f.get("name") or "unknown"

        for sym in f.get("called_symbols", []):
            if "sym." in sym:
                dst = sym.split()[-1]
                edges.add((src, dst))

    return edges


def export_dot(call_graph):
    lines = ["digraph malware_call_graph {"]

    for src, dst in call_graph:
        lines.append(f'  "{src}" -> "{dst}";')

    lines.append("}")
    return "\n".join(lines)
