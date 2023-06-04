from stix2 import Filter
from stix2 import MemoryStore
import requests
from .models import MITRETactic, MITRETechnique, MITREMitigation

class StixParser():
    """
    Get and parse STIX data creating Tactics and Techniques objects
    Get the ATT&CK STIX data from MITRE/CTI GitHub repository. 
    Domain should be 'enterprise-attack', 'mobile-attack', or 'ics-attack'. Branch should typically be master.
    """

    def __init__(self, repo_url, domain):
        self.url = repo_url
        self.domain = domain

        stix_json = requests.get(f"{self.url}/{domain}/{domain}.json").json()

        self.src = MemoryStore(stix_data=stix_json['objects'])

    
    def get_data(self):
        self._get_tactics()
        self._get_techniques()
        self._get_mitigations()


    def _get_tactics(self):
        """
        Get and parse tactics from STIX data
        """

        # Extract tactics
        tactics_stix = self.src.query([ Filter('type', '=', 'x-mitre-tactic') ])

        self.tactics = list()

        for tactic in tactics_stix:
            tactic_obj = MITRETactic(tactic['name'])
            # Extract external references, including the link to mitre
            ext_refs = tactic.get('external_references', [])

            for ext_ref in ext_refs:
                if ext_ref['source_name'] == 'mitre-attack':
                    tactic_obj.id = ext_ref['external_id']
                
                tactic_obj.references = {'name': ext_ref['source_name'], 'url': ext_ref['url']}

            tactic_obj.description = tactic['description']

            self.tactics.append(tactic_obj)

    def _get_techniques(self):
        """
        Get and parse techniques from STIX data
        """

        # Extract techniques
        tech_stix = self.src.query([ Filter('type', '=', 'attack-pattern') ])

        self.techniques = list()

        for tech in tech_stix:
            technique_obj = MITRETechnique(tech['name'])

            technique_obj.internal_id = tech['id']

            # Extract external references, including the link to mitre
            ext_refs = tech.get('external_references', [])

            for ext_ref in ext_refs:
                if ext_ref['source_name'] == 'mitre-attack':
                    technique_obj.id = ext_ref['external_id']
                    
                if 'url' in ext_ref:
                    technique_obj.references = {'name': ext_ref['source_name'], 'url': ext_ref['url']}

            kill_chain = tech.get('kill_chain_phases', [])

            for kill_phase in kill_chain:
                technique_obj.kill_chain_phases = kill_phase

            technique_obj.is_subtechnique = tech['x_mitre_is_subtechnique']

            technique_obj.description = tech['description']

            self.techniques.append(technique_obj)


    def _get_mitigations(self):
        """
        Get and parse techniques from STIX data
        """

        # Extract mitigations
        mitigations_stix = self.src.query([ Filter('type', '=', 'course-of-action') ])

        self.mitigations = list()

        for mitigation in mitigations_stix:
            mitigation_obj = MITREMitigation(mitigation['name'])
            
            mitigation_obj.internal_id = mitigation['id']
            mitigation_obj.description = mitigation['description']

            ext_refs = mitigation.get('external_references', [])

            for ext_ref in ext_refs:
                if ext_ref['source_name'] == 'mitre-attack':
                    mitigation_obj.id = ext_ref['external_id']
                    
            mitigation_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'mitigates'), Filter('source_ref', '=', mitigation_obj.internal_id) ])

            for relationship in mitigation_relationships:
                for technique in self.techniques:
                    if technique.internal_id == relationship['target_ref']:
                        mitigation_obj.mitigates = {'technique': technique, 'description': relationship.get('description', '') }
                        technique.mitigations = {'mitigation': mitigation_obj, 'description': relationship.get('description', '') }

            self.mitigations.append(mitigation_obj)
