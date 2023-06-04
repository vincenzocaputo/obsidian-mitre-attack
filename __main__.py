from src.stix_parser import StixParser
from src.markdown_generator import MarkdownGenerator
import argparse
import os
import yaml

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Downdload MITRE ATT&CK STIX data and parse it to Obsidian markdown notes')

    parser.add_argument('-d', '--domain', help="Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'", default='enterprise-attack')
    parser.add_argument('-o', '--output', help="Output directory in which the notes will be saved. It should be placed inside a Obsidian vault.", required=True)

    args = parser.parse_args()

    if args.output:
        output_dir = args.output
    else:
        exit()

    if args.domain:
        domain = args.domain
        if domain not in ('enterprise-attack', 'mobile-attack', 'ics-attack'):
            raise ValueError("The domain provided is not supported")

    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    with open('config.yml', 'r') as fd:
        config = yaml.safe_load(fd)

    parser = StixParser(config['repository_url'], domain)

    parser.get_data()

    markdown_generator = MarkdownGenerator(output_dir, parser.tactics, parser.techniques, parser.mitigations)
    markdown_generator.create_tactic_notes()
    markdown_generator.create_technique_notes()
    markdown_generator.create_mitigation_notes()

    
