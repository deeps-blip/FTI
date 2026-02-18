import r2pipe


class RadareRunner:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.r2 = r2pipe.open(binary_path)

        # Apply relocations and cache binary
        self.r2.cmd("e bin.relocs.apply=true")
        self.r2.cmd("e bin.cache=true")

    def analyze(self):
        # Stable deeper analysis
        self.r2.cmd("aaaa")

    def cmdj(self, command: str):
        return self.r2.cmdj(command)

    def quit(self):
        self.r2.quit()


def main():
    # IMPORT INSIDE FUNCTION (critical)
    from analyzer import analyze_all_samples

    results = analyze_all_samples()

    for sample, data in results.items():
        print("\n==============================")
        print(f"Sample: {sample}")

        if "error" in data:
            print("Error:", data["error"])
            continue

        print("Findings:", data.get("findings"))
        print("Behavioral Risk Score:", data.get("behavioral_risk"))


if __name__ == "__main__":
    main()
