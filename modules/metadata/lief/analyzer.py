import os

from lief import ELF

class LiefAnalyzer(object):

    def __init__(self):
        pass

    def analyze(self, filepath=None):
        self.filepath = filepath
        results = {}
        if self.filepath is not None:
            elf_binary = ELF.Builder(self.filepath).getBuild()
            sections = elf_binary.getSections()
            results["sections"] = {}
            for idx, section in enumerate(sections):
                results["sections"][idx] = {'name': section.name, 'entropy': section.entropy}

            results["entry_point"] = elf_binary.getHeader().entryPoint

        return results





