from stix2 import Filter
from stix2 import MemoryStore
from pathlib import Path
from . import ROOT

import requests
import os


class MarkdownGenerator():

    def __init__(self, output_dir, tactics=[], techniques=[]):
        self.output_dir = os.path.join(ROOT, output_dir)
        self.tactics = tactics
        self.techniques = techniques

    def create_tactic_notes(self):
        tactics_dir = os.path.join(self.output_dir, "tactics")
        if not os.path.exists(tactics_dir):
            os.mkdir(tactics_dir)

        for tactic in self.tactics:
            tactic_file = os.path.join(tactics_dir, f"{tactic.name}.md")

            with open(tactic_file, 'w') as fd:
                content = f"---\nalias: {tactic.id}\n---"
                content += f"\n{tactic.description}\n\n---\n"
                
                content += f"### References\n"
                for ref in tactic.references.keys():
                    content += f"- {ref}: {tactic.references[ref]}\n"
                fd.write(content)


    def create_technique_notes(self):
        techniques_dir = os.path.join(self.output_dir, "techniques")
        if not os.path.exists(techniques_dir):
            os.mkdir(techniques_dir)

        for technique in self.techniques:
            technique_file = os.path.join(techniques_dir, f"{technique.id}.md")

            with open(technique_file, 'w') as fd:
                content = f"---\nalias: {technique.name}\n---\n\n"

                content += f"## {technique.name}\n\n"
                content += f"{technique.description}\n\n\n"

                for kill_chain in technique.kill_chain_phases:
                    if kill_chain['kill_chain_name'] == 'mitre-attack':
                        tactic = [ t for t in self.tactics if t.name.lower().replace(' ', '-') == kill_chain['phase_name'].lower() ]
                        if tactic:
                            content += f"### Tactic\n\n"
                            for t in tactic:
                                content += f"- [[{t.name}]] ({t.id})\n" 


                if not technique.is_subtechnique:
                    content += f"\n### Sub-techniques\n"
                    subtechniques = [ subt for subt in self.techniques if subt.is_subtechnique and technique.id in subt.id ]
                    if subtechniques:
                        content += f"\n| ID | Name |\n| --- | --- |\n"
                    for subt in subtechniques:
                        content += f"| [[{subt.id}]] | {subt.name} |\n"


                content += f"\n\n---\n### References\n\n"
                for ref in technique.references.keys():
                    content += f"- {ref}: {technique.references[ref]}\n"

                fd.write(content)
