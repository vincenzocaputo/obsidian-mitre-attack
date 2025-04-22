from jinja2 import Environment, FileSystemLoader
from stix2 import Filter
from stix2 import MemoryStore
from pathlib import Path
from . import ROOT

import requests
import os
import json
import uuid
import re

class MarkdownGenerator():

    def __init__(self, output_dir=None, tactics=[], techniques=[], mitigations=[], groups=[], software=[]):
        if output_dir:
            self.output_dir = os.path.join(ROOT, output_dir)
        self.tactics = tactics
        self.techniques = techniques
        self.mitigations = mitigations
        self.groups = groups
        self.software = software
        self.environment = Environment(loader=FileSystemLoader(os.path.join(ROOT, "res/templates/")))
        self.environment.filters["parse_description"] = MarkdownGenerator.parse_description

    @staticmethod
    def parse_description(description, references=[]):
        description = description.replace('\n', '<br/>')
        description = description.replace('</code>', '`')
        description = description.replace('<code>', '`')

        for ref in references:
            description = re.sub(fr'\(Citation: {ref["source_name"]}\)', f'[^{ref["id"]}] ', description)
        return description

    def create_tactic_notes(self):
        template = self.environment.get_template("tactic.md")
        tactics_dir = os.path.join(self.output_dir, "tactics")
        if not os.path.exists(tactics_dir):
            os.mkdir(tactics_dir)

        for tactic in self.tactics:
            for ref in tactic.references:
                if ref[0] == 'mitre-attack':
                    mitre_attack = ref[1]

            content = template.render(
                    aliases = [tactic.id],
                    mitre_attack = mitre_attack,
                    title = tactic.id,
                    description = tactic.description
            )
            tactic_file = os.path.join(tactics_dir, f"{tactic.name}.md")

            with open(tactic_file, 'w') as fd:
                fd.write(content)


    def create_technique_notes(self):
        template = self.environment.get_template("technique.md")
        techniques_dir = os.path.join(self.output_dir, "techniques")
        if not os.path.exists(techniques_dir):
            os.mkdir(techniques_dir)

        for technique in self.techniques:
            footnote_id = 1
            references = {}
            for ref in technique.references:
                if ref[0] == 'mitre-attack':
                    mitre_attack = ref[1]
                    pass
                ref_url = ref[1]
                if ref_url not in references:
                    references[ref_url] = {
                        'id': footnote_id,
                        'source_name': ref[0]
                    }
                    footnote_id += 1

            tactics = []
            for kill_chain in technique.kill_chain_phases:
                if kill_chain["kill_chain_name"] == 'mitre-attack':
                    tactics += [ t.name for t in self.tactics if t.name.lower().replace(' ', '-') == kill_chain["phase_name"].lower() ]

            content = template.render(
                    aliases = [technique.id],
                    mitre_attack = mitre_attack,
                    tactics = tactics,
                    platforms = technique.platforms,
                    permissions_required = technique.permissions_required,
                    title = technique.id,
                    description = technique.description,
                    procedures = [{"name": sw["software"].name,
                                 "id": sw["software"].id,
                                 "description": sw["description"]} for sw in technique.software] +
                                 [{"name": g["group"].name,
                                 "id": g["group"].id,
                                 "description": g["description"]} for g in technique.groups],
                    mitigations = [{"name": m["mitigation"].name,
                                 "id": m["mitigation"].id,
                                 "description": m["description"]} for m in technique.mitigations],
                    subtechniques = [ subt for subt in self.techniques if subt.is_subtechnique and technique.id in subt.id ],
                    references = [{"id": value["id"],
                                   "source_name": value["source_name"],
                                   "url": url} for url, value in references.items() ]
            )

            technique_file = os.path.join(techniques_dir, f"{technique.name}.md")

            with open(technique_file, 'w') as fd:
                fd.write(content)


    def create_mitigation_notes(self):
        template = self.environment.get_template("mitigation.md")
        
        mitigations_dir = os.path.join(self.output_dir, "mitigations")
        if not os.path.exists(mitigations_dir):
            os.mkdir(mitigations_dir)

        for mitigation in self.mitigations:
            mitigation_file = os.path.join(mitigations_dir, f"{mitigation.name}.md")

            footnote_id = 1
            references = {}
            for ref in mitigation.references:
                if ref[0] == 'mitre-attack':
                    mitre_attack = ref[1]
                    pass
                ref_url = ref[1]
                if ref_url not in references:
                    references[ref_url] = {
                            'id': footnote_id,
                            'source_name': ref[0]
                    }
                    footnote_id += 1

            content = template.render(
                    aliases = [mitigation.id],
                    mitre_attack = mitre_attack,
                    title = mitigation.id,
                    description = mitigation.description,
                    techniques = [{"name": t["technique"].name,
                                   "id": t["technique"].id,
                                   "description": t["description"]} for t in mitigation.mitigates ]
            )
            with open(mitigation_file, 'w') as fd:
                fd.write(content)


    def create_group_notes(self):
        template = self.environment.get_template("group.md")

        groups_dir = os.path.join(self.output_dir, "groups")
        if not os.path.exists(groups_dir):
            os.mkdir(groups_dir)

        for group in self.groups:
            group_file = os.path.join(groups_dir, f"{group.name}.md")

            footnote_id = 1
            references = {}
            for ref in group.references:
                if ref[0] == 'mitre-attack':
                    mitre_attack = ref[1]
                    pass
                ref_url = ref[1]
                if ref_url not in references:
                    references[ref_url] = {
                            'id': footnote_id,
                            'source_name': ref[0]
                    }
                    footnote_id += 1

            content = template.render(
                    aliases = group.aliases,
                    mitre_attack = mitre_attack,
                    title = group.id,
                    description = group.description,
                    techniques = [{"name": t["technique"].name,
                                   "id": t["technique"].id,
                                   "description": t["description"]} for t in group.techniques_used],
                    software = [{"name": s["software"].name,
                                 "id": s["software"].id,
                                 "description": s["description"]} for s in group.software_used],
                    references = [{"id": value["id"],
                                   "source_name": value["source_name"],
                                   "url": url} for url, value in references.items() ]
            )
            with open(group_file, 'w') as fd:
                fd.write(content)

    def create_software_notes(self):
        template = self.environment.get_template("software.md")

        software_dir = os.path.join(self.output_dir, "software")
        if not os.path.exists(software_dir):
            os.mkdir(software_dir)


        for software in self.software:
            footnote_id = 1
            references = {}
            for ref in software.references:
                if ref[0] == 'mitre-attack':
                    mitre_attack = ref[1]
                    pass
                ref_url = ref[1]
                if ref_url not in references:
                    references[ref_url] = {
                            'id': footnote_id,
                            'source_name': ref[0]
                    }
                    footnote_id += 1

            techniques_used = []
            for tech in software.techniques_used:
                techniques_used.append({
                    'name': tech["technique"].name,
                    'id': tech["technique"].id,
                    'description': tech["description"]
                })
            groups = []
            for group in software.groups:
                groups.append({
                        'name': group["group"].name,
                        'id': group["group"].id,
                        'description': group["description"]
                    })

            content = template.render(
                    aliases = [software.id],
                    mitre_attack = mitre_attack,
                    title = software.id,
                    description = software.description,
                    techniques = techniques_used,
                    groups = groups,
                    references = [{"id": value["id"],
                                   "source_name": value["source_name"],
                                   "url": url} for url, value in references.items() ]
            )
            software_file = os.path.join(software_dir, f"{software.name}.md")

            with open(software_file, 'w') as fd:
                fd.write(content)

    def create_canvas(self, canvas_name, filtered_techniques):
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


        rows = dict()
        height = 144
        y = 50
        max_height = y
        for technique in self.techniques:
            if technique.id in filtered_techniques:
                if not technique.is_subtechnique:
                    for kill_chain in technique.kill_chain_phases:
                        if kill_chain["kill_chain_name"] == 'mitre-attack':
                            tactic = [ t for t in self.tactics if t.name.lower().replace(' ', '-') == kill_chain["phase_name"].lower() ]
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
                    canvas["nodes"].append(technique_node)
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
                            canvas["nodes"].append(subtech_node)
                    
                    rows[tactic[0].name] = y
                    if y > max_height:
                        max_height = y

        for tactic in self.tactics:
            container_node = {
                        "type": "group",
                        "label": f"{tactic.name}",
                        "id": uuid.uuid4().hex,
                        "x": columns[tactic.name],
                        "y": 0,
                        "width": 500,
                        "height": max_height + 20
                    }
            canvas["nodes"].append(container_node)
                        
            
        with open(f"{canvas_name}.canvas", 'w') as fd:
            fd.write(json.dumps(canvas, indent=2))
            

