from loguru import logger
from tqdm import tqdm
from stix2 import Filter
from stix2 import MemoryStore
import requests
import json

from .models import (MITRETactic,
                     MITRETechnique,
                     MITREMitigation,
                     MITREGroup,
                     MITRESoftware)

class StixParser():
    """
    Get and parse STIX data creating Tactics and Techniques objects
    Get the ATT&CK STIX data from MITRE/CTI GitHub repository. 
    Domain should be 'enterprise-attack', 'mobile-attack', or 'ics-attack'. Branch should typically be master.

    """

    def __init__(self, repo_url, domain, version=None):
        mitre_repo_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"

        if repo_url != mitre_repo_url:
            logger.warning("You have defined a different source for ATT&CK STIX data. The domain and version option will be ignored.")
            if repo_url.startswith('http'):
                response = requests.get(repo_url)
                if response.status_code == 200:
                    try:
                        stix_json = response.json()
                    except requests.JSONDecodeError:
                        logger.critical(f"The STIX data at {repo_url} is not valid.")
                        exit(-1)
                else:
                    logger.critical(f"An error while reaching the remote source: {response.status_code} - {response.reason}")
                    exit(-1)
            else:
                try:
                    with open(repo_url, 'r') as fd:
                        stix_json = json.loads(fd.read())
                except json.JSONDecodeError:
                    logger.critical("You have provided an invalid JSON file")
                    exit(-1)
                except FileNotFoundError:
                    logger.critical("The file defined in the config.yml does not exist")
                    exit(-1)
        else:
            if version:
                logger.info(f"Downloading STIX data for domain {domain}, version {version}")
                response = requests.get(f"{repo_url}/{domain}/{domain}-{version}.json")
                if response.status_code == 200:
                    try:
                        stix_json = response.json()
                    except requests.JSONDecodeError:
                        logger.critical(f"The STIX data at {repo_url} is not valid.")
                        exit(-1)
                else:
                    logger.critical(f"An error while reaching the remote source: {response.status_code} - {response.reason}")
                    exit(-1)
            else:
                response = requests.get(f"{repo_url}/{domain}/{domain}.json")
                if response.status_code == 200:
                    try:
                        stix_json = response.json()
                    except requests.RequestsJSONDecodeError:
                        logger.critical(f"The STIX data at {repo_url} is not valid.")
                        exit(-1)
                else:
                    logger.critical(f"An error while reaching the remote source: {response.status_code} - {response.reason}")
                    exit(-1)
        if not 'objects' in stix_json:
            logger.critical("The source provided does not contain a valid STIX bundle")
            exit(-1)
        self.src = MemoryStore(stix_data=stix_json['objects'])

    
    def get_data(self, tactics=False,
                 techniques=False,
                 mitigations=False,
                 groups=False,
                 software=False):
        
        self.tactics=list()
        self.techniques=list()
        self.mitigations=list()
        self.groups=list()
        self.software=list()
        if tactics:
            logger.info("Extracting Tactics...")
            self._get_tactics()
        if techniques:
            logger.info("Extracting Techniques...")
            self._get_techniques()
        if mitigations:
            logger.info("Extracting Mitigations...")
            self._get_mitigations()
        if groups:
            logger.info("Extracting Groups...")
            self._get_groups()
        if software:
            logger.info("Extracting Software...")
            self._get_software()


    def _get_tactics(self):
        """
        Get and parse tactics from STIX data
        """

        # Extract tactics
        tactics_stix = self.src.query([ Filter('type', '=', 'x-mitre-tactic') ])

        self.tactics = list()

        for tactic in tqdm(tactics_stix):
            tactic_obj = MITRETactic(tactic['name'])
            # Extract external references, including the link to mitre
            ext_refs = tactic.get('external_references', [])

            for ext_ref in ext_refs:
                if ext_ref['source_name'] == 'mitre-attack':
                    tactic_obj.id = ext_ref['external_id']
                
                tactic_obj.references = (ext_ref['source_name'], ext_ref['url'])

            tactic_obj.description = tactic['description']

            self.tactics.append(tactic_obj)

    def _get_techniques(self):
        """
        Get and parse techniques from STIX data
        """

        # Extract techniques
        tech_stix = self.src.query([ Filter('type', '=', 'attack-pattern') ])

        self.techniques = list()

        for tech in tqdm(tech_stix):
            if ('x_mitre_deprecated' not in tech or not tech['x_mitre_deprecated']) and not tech['revoked']:
                technique_obj = MITRETechnique(tech['name'])

                technique_obj.internal_id = tech['id']

                # Extract external references, including the link to mitre
                ext_refs = tech.get('external_references', [])

                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        technique_obj.id = ext_ref['external_id']
                        
                    technique_obj.references = (ext_ref['source_name'], ext_ref.get('url',''))

                kill_chain = tech.get('kill_chain_phases', [])

                for kill_phase in kill_chain:
                    technique_obj.kill_chain_phases = kill_phase

                technique_obj.is_subtechnique = tech['x_mitre_is_subtechnique']

                technique_obj.platforms = tech.get('x_mitre_platforms', [])
                technique_obj.permissions_required = tech.get('x_mitre_permissions_required', [])
                technique_obj.description = tech['description']

                self.techniques.append(technique_obj)


    def _get_mitigations(self):
        """
        Get and parse techniques from STIX data
        """

        # Extract mitigations
        mitigations_stix = self.src.query([ Filter('type', '=', 'course-of-action') ])

        self.mitigations = list()

        for mitigation in tqdm(mitigations_stix):
            if not mitigation.get('x_mitre_deprecated', False): 
                mitigation_obj = MITREMitigation(mitigation['name'])
                
                mitigation_obj.internal_id = mitigation['id']
                mitigation_obj.description = mitigation['description']

                ext_refs = mitigation.get('external_references', [])

                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        mitigation_obj.id = ext_ref['external_id']
                    mitigation_obj.references = (ext_ref['source_name'], ext_ref.get('url',''))
                        
                mitigation_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'mitigates'), Filter('source_ref', '=', mitigation_obj.internal_id) ])

                for relationship in mitigation_relationships:
                    for technique in self.techniques:
                        refs = relationship.get('external_references', [])
                        for ext_ref in refs:
                            mitigation_obj.references = (ext_ref['source_name'], ext_ref.get('url',''))
                            technique.references = (ext_ref['source_name'], ext_ref.get('url',''))
                        if technique.internal_id == relationship['target_ref']:
                            mitigation_obj.mitigates = {'technique': technique, 'description': relationship.get('description', '') }
                            technique.mitigations = {'mitigation': mitigation_obj, 'description': relationship.get('description', '') }

                self.mitigations.append(mitigation_obj)

    def _get_groups(self):
        """
        Get and parse groups from STIX data
        """

        # Extract groups
        groups_stix = self.src.query([ Filter('type', '=', 'intrusion-set') ])

        self.groups = list()

        for group in tqdm(groups_stix):
            if group.get('x_mitre_deprecated', False) != 'true':
                group_obj = MITREGroup(group['name'])

                group_obj.internal_id = group['id']

                # Extract external references, including the link to mitre
                ext_refs = group.get('external_references', [])
                
                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        group_obj.id = ext_ref['external_id']
                        
                    group_obj.references = (ext_ref['source_name'], ext_ref.get('url', ''))

                group_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', group_obj.internal_id) ])

                for relationship in group_relationships:
                    for technique in self.techniques:
                        if technique.internal_id == relationship['target_ref']:
                            refs = relationship.get('external_references', [])
                            for ext_ref in refs:
                                group_obj.references = (ext_ref['source_name'], ext_ref['url'])
                                technique.references = (ext_ref['source_name'], ext_ref['url'])
                            group_obj.techniques_used = {'technique': technique, 'description': relationship.get('description', '') }
                            technique.groups = {'group': group_obj, 'description': relationship.get('description', '') }
                group_obj.aliases = group.get('aliases', [])
                group_obj.description = group.get('description', '')

                self.groups.append(group_obj)

    def _get_software(self):
        """
        Get and parse software objects from STIX data
        """

        # Extract software (tools, malware)
        software_stix = self.src.query([ Filter('type', '=', 'tool') ]) + self.src.query([ Filter('type', '=', 'malware') ])

        self.software = list()

        for sw in tqdm(software_stix):
            if 'x_mitre_deprecated' not in sw or not sw['x_mitre_deprecated']:
                software_obj = MITRESoftware(sw['name'])

                software_obj.internal_id = sw['id']

                # Extract external references, including the link to mitre
                ext_refs = sw.get('external_references', [])

                for ext_ref in ext_refs:
                    if ext_ref['source_name'] == 'mitre-attack':
                        software_obj.id = ext_ref['external_id']
                        
                    software_obj.references = (ext_ref['source_name'], ext_ref.get('url', ''))

                group_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('target_ref', '=', software_obj.internal_id) ])
                for relationship in group_relationships:
                    for group in self.groups:
                        if group.internal_id == relationship['source_ref']:
                            refs = relationship.get('external_references', [])
                            for ext_ref in refs:
                                software_obj.references = (ext_ref['source_name'], ext_ref['url'])
                                group.references = (ext_ref['source_name'], ext_ref['url'])
                            group.software_used = {'software': software_obj, 'description': relationship.get('description', '')}
                            software_obj.groups = {'group': group, 'description': relationship.get('description', '')}

                techniques_relationships = self.src.query([ Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', software_obj.internal_id) ])
                for relationship in techniques_relationships:
                    for technique in self.techniques:
                        if technique.internal_id == relationship['target_ref']:
                            refs = relationship.get('external_references', [])
                            for ext_ref in refs:
                                software_obj.references = (ext_ref['source_name'], ext_ref['url'])
                                technique.references = (ext_ref['source_name'], ext_ref['url'])
                            software_obj.techniques_used = {'technique': technique, 'description': relationship.get('description', '')}
                            technique.software = {'software': software_obj, 'description': relationship.get('description', '')}

                software_obj.description = sw['description']
                self.software.append(software_obj)
