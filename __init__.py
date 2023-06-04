from src.stix_parser import StixParser
from src.markdown_generator import MarkdownGenerator
import os
import yaml

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    with open('config.yml', 'r') as fd:
        config = yaml.safe_load(fd)

    parser = StixParser(config['repository_url'], config['domain'])

    tactics = parser.get_tactics()
    techniques = parser.get_techniques()

    markdown_generator = MarkdownGenerator(config['output_dir'], tactics, techniques)
    markdown_generator.create_tactic_notes()
    markdown_generator.create_technique_notes()

    
