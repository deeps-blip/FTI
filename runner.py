import r2pipe


class RadareRunner:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.r2 = r2pipe.open(binary_path)

        # Apply relocations and cache binary
        self.r2.cmd("e bin.relocs.apply=true")
        self.r2.cmd("e bin.cache=true")

    def analyze(self):
        # Use aaaa for deeper analysis, but stable
        self.r2.cmd("aaaa")

    def cmdj(self, command: str):
        return self.r2.cmdj(command)

    def quit(self):
        self.r2.quit()
