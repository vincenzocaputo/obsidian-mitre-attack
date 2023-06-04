from stix2 import Filter
from stix2 import MemoryStore
import requests
from .models import MITRETactic

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



    def get_tactics(self):
        """
        Get and parse tactics from STIX data

        :return: Array of Tactics object containing information about tactics
        """

        # Extract tactics
        tactics_stix = self.src.query([ Filter('type', '=', 'x-mitre-tactic') ])

        tactics = list()

        for tactic in tactics_stix:
            tactic_obj = MITRETactic(tactic['name'])
            # Extract external references, including the link to mitre
            ext_refs = tactic.get('external_references', [])

            for ext_ref in ext_refs:
                if ext_ref['source_name'] == 'mitre-attack':
                    tactic_obj.id = ext_ref['external_id']
                
                tactic_obj.references = {'name': ext_ref['source_name'], 'url': ext_ref['url']}

            tactic_obj.description = tactic['description']

            tactics.append(tactic_obj)
        return tactics


    def get_techniques(self):
        """
        Get and parse techniques from STIX data

        :return: Array of Techniques object containing information about techniques
        """

        # Extract techniques
        tech_stix = self.src.query([ Filter('type', '=', 'attack-pattern') ])

        techniques = list()

        for tech in techniques_stix:
            techniques_obj = Techniques(tech['name'])
            # Extract external references, including the link to mitre
            ext_refs = techniques.get('external_references', [])

            for ext_ref in ext_refs:
                if ext_ref['source_name'] == 'mitre-attack':
                    tactic_obj.id = ext_ref['external_id']
                    tactic_obj.mitre_url = ext_ref['url']

            tactic_obj.description = tactic['description']

            tactics.append(tactic_obj)
        return tactics
