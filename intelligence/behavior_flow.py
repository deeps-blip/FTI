def build_behavior_flow(functions):
    flow = set()

    for f in functions:
        for sym in f["called_symbols"]:
            if "send" in sym or "recv" in sym:
                flow.add("entry → network_communication")

            if "reg" in sym:
                flow.add("execution → persistence")

            if "crypt" in sym:
                flow.add("data → encryption")

    return list(flow)
