from stix2 import Filter
from stix2 import MemoryStore
from pathlib import Path
from . import ROOT

import requests
import os


class MarkdownGenerator():

    def __init__(self, output_dir):
        self.output_dir = os.path.join(ROOT, output_dir)


    def create_tactic_notes(self, tactics):
        tactics_dir = os.path.join(self.output_dir, "tactics")
        if not os.path.exists(tactics_dir):
            os.mkdir(tactics_dir)

        for tactic in tactics:
            tactic_file = os.path.join(tactics_dir, f"{tactic.name}.md")

            with open(tactic_file, 'w') as fd:
                content = f"---\nalias: {tactic.id}\n---"
                content += f"\n{tactic.description}\n\n---\n"
                
                content += f"## References\n"
                for ref in tactic.references.keys():
                    content += f"- {ref}: {tactic.references[ref]}\n"
                fd.write(content)


