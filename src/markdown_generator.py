from stix2 import Filter
from stix2 import MemoryStore
from pathlib import Path
from . import ROOT

import requests
import os
import json
import uuid

class MarkdownGenerator():

    def __init__(self, output_dir, tactics=[], techniques=[], mitigations=[], groups=[]):
        self.output_dir = os.path.join(ROOT, output_dir)
        self.tactics = tactics
        self.techniques = techniques
        self.mitigations = mitigations
        self.groups = groups


    def create_tactic_notes(self):
        tactics_dir = os.path.join(self.output_dir, "tactics")
        if not os.path.exists(tactics_dir):
            os.mkdir(tactics_dir)

        for tactic in self.tactics:
            tactic_file = os.path.join(tactics_dir, f"{tactic.name}.md")

            with open(tactic_file, 'w') as fd:
                content = f"---\nalias: {tactic.id}\n---"
                content += f"\n\n## {tactic.id}\n"
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
            technique_file = os.path.join(techniques_dir, f"{technique.name}.md")

            with open(technique_file, 'w') as fd:
                content = f"---\nalias: {technique.id}\n---\n\n"

                content += f"## {technique.id}\n\n"
                content += f"{technique.description}\n\n\n"


                content += f"### Tactic\n"
                for kill_chain in technique.kill_chain_phases:
                    if kill_chain['kill_chain_name'] == 'mitre-attack':
                        tactic = [ t for t in self.tactics if t.name.lower().replace(' ', '-') == kill_chain['phase_name'].lower() ]
                        if tactic:
                            for t in tactic:
                                content += f"- [[{t.name}]] ({t.id})\n" 

                content += f"\n### Platforms\n"
                for platform in technique.platforms:
                    content += f"- {platform}\n"

                content += f"\n### Permissions Required\n"
                for permission in technique.permissions_required:
                    content += f"- {permission}\n"

                content += f"\n### Mitigations\n"
                if technique.mitigations:
                    content += f"\n| ID | Name | Description |\n| --- | --- | --- |\n"
                    for mitigation in technique.mitigations:
                        description = mitigation['description'].replace('\n', '<br />')
                        content += f"| [[{mitigation['mitigation'].name}\|{mitigation['mitigation'].id}]] | {mitigation['mitigation'].name} | {description} |\n"

                if not technique.is_subtechnique:
                    content += f"\n### Sub-techniques\n"
                    subtechniques = [ subt for subt in self.techniques if subt.is_subtechnique and technique.id in subt.id ]
                    if subtechniques:
                        content += f"\n| ID | Name |\n| --- | --- |\n"
                    for subt in subtechniques:
                        content += f"| [[{subt.name}\|{subt.id}]] | {subt.name} |\n"


                content += f"\n\n---\n### References\n\n"
                for ref in technique.references.keys():
                    content += f"- {ref}: {technique.references[ref]}\n"

                fd.write(content)


    def create_mitigation_notes(self):
        mitigations_dir = os.path.join(self.output_dir, "mitigations")
        if not os.path.exists(mitigations_dir):
            os.mkdir(mitigations_dir)

        for mitigation in self.mitigations:
            mitigation_file = os.path.join(mitigations_dir, f"{mitigation.name}.md")

            with open(mitigation_file, 'w') as fd:
                content = f"---\nalias: {mitigation.id}\n---\n\n"

                content += f"## {mitigation.id}\n\n"
                content += f"{mitigation.description}\n\n\n"


                content += f"### Techniques Addressed by Mitigation\n"
                if mitigation.mitigates:
                    content += f"\n| ID | Name | Description |\n| --- | --- | --- |\n"
                    for technique in mitigation.mitigates:
                        description = technique['description'].replace('\n', '<br />')
                        content += f"| [[{technique['technique'].name}\|{technique['technique'].id}]] | {technique['technique'].name} | {description} |\n"


                fd.write(content)


    def create_group_notes(self):
        groups_dir = os.path.join(self.output_dir, "groups")
        if not os.path.exists(groups_dir):
            os.mkdir(groups_dir)

        for group in self.groups:
            group_file = os.path.join(groups_dir, f"{group.name}.md")

            with open(group_file, 'w') as fd:
                content = f"---\nalias: {', '.join(group.aliases)}\n---\n\n"

                content += f"## {group.id}\n\n"
                content += f"{group.description}\n\n\n"

                content += f"### Techniques Used\n"

                if group.techniques_used:
                    content += f"\n| ID | Name | Use |\n| --- | --- | --- |\n"
                    for technique in group.techniques_used:
                        description = technique['description'].replace('\n', '<br />')
                        content += f"| [[{technique['technique'].name}\|{technique['technique'].id}]] | {technique['technique'].name} | {description} |\n"

                fd.write(content)


    def create_canvas(self):
        canvas = {
                "nodes": [],
                "edges": []
            }

        x = 0
        width = 450
        columns = {
                    "Reconnaissance": 0,
                    "Resource Development": 500,
                    "Initial Access": 1000,
                    "Execution": 1500,
                    "Persistence": 2000,
                    "Privilege Escalation": 2500,
                    "Defense Evasion": 3000,
                    "Credential Access": 3500,
                    "Discovery": 4000,
                    "Lateral Movement": 4500,
                    "Collection": 5000,
                    "Command and Control": 5500,
                    "Exfiltration": 6000,
                    "Impact": 6500,
                }
        for tactic in self.tactics:
            container_node = {
                        "type": "group",
                        "label": f"{tactic.name}",
                        "id": uuid.uuid4().hex,
                        "x": columns[tactic.name],
                        "y": 0,
                        "width": 500,
                        "height": 24744
                    }
            canvas['nodes'].append(container_node)


        rows = dict()
        height = 144
        y = 50
        for technique in self.techniques:
            if not technique.is_subtechnique:
                for kill_chain in technique.kill_chain_phases:
                    if kill_chain['kill_chain_name'] == 'mitre-attack':
                        tactic = [ t for t in self.tactics if t.name.lower().replace(' ', '-') == kill_chain['phase_name'].lower() ]
                        if tactic:
                            if tactic[0].name in rows.keys():
                                y = rows[tactic[0].name]
                            else:
                                y = 50
                                rows[tactic[0].name] = y
                            x = columns[tactic[0].name] + 20

                technique_node = {
                            "type": "file",
                            "file": f"techniques/{technique.name}.md",
                            "id": uuid.uuid4().hex,
                            "x": x,
                            "y": y,
                            "width": 450,
                            "height": height
                        }
                canvas['nodes'].append(technique_node)
                y = y + height + 20
                subtechniques = [ subt for subt in self.techniques if subt.is_subtechnique and technique.id in subt.id ]
                if subtechniques:
                    for subt in subtechniques:
                        subtech_node = {
                                    "type": "file",
                                    "file": f"techniques/{subt.name}.md",
                                    "id": uuid.uuid4().hex,
                                    "x": x + 50,
                                    "y": y,
                                    "width": 400,
                                    "height": height
                                }
                        y = y + height + 20
                        canvas['nodes'].append(subtech_node)
                rows[tactic[0].name] = y
                        
            
        with open('matrix.canvas', 'w') as fd:
            fd.write(json.dumps(canvas, indent=2))
            

