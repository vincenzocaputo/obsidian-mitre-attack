from src.stix_parser import StixParser
from src.markdown_generator import MarkdownGenerator
from src.view import create_graph_json
from src.markdown_reader import MarkdownReader

from loguru import logger

import argparse
import os
import sys
import yaml
import re

if __name__ == '__main__':
    logger.remove()
    logger.add(sys.stdout, colorize=True, format="[<level>{level}</level>] - <level>{message}</level>")

    parser = argparse.ArgumentParser(description='Downdload MITRE ATT&CK STIX data and parse it to Obsidian markdown notes')

    parser.add_argument('-d', '--domain', help="Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'", default='enterprise-attack')
    parser.add_argument('-o', '--output', help="Output directory in which the notes will be saved. It should be placed inside a Obsidian vault.")
    parser.add_argument('--generate-hyperlinks', help="Generate techniques hyperlinks in a markdown note file", action="store_true")
    parser.add_argument('--generate-matrix', help="Create ATT&CK matrix starting from a markdown note file", action="store_true")
    parser.add_argument('--path', help="Filepath to the markdown note file")

    args = parser.parse_args()

    with open('config.yml', 'r') as fd:
        config = yaml.safe_load(fd)

    if args.domain:
        domain = args.domain
        if domain not in ('enterprise-attack', 'mobile-attack', 'ics-attack'):
            logger.error(f"The domain {domain} is not suported")
            exit(-1)

    if args.generate_hyperlinks:
        if args.path:
            if os.path.isfile(args.path) and args.path.endswith('.md'):
                parser = StixParser(config['repository-url'], domain, config.get('version'))
                logger.info("Extracting objects from STIX data")
                parser.get_data(techniques=True)
                markdown_reader = MarkdownReader(args.path)
                markdown_reader.create_hyperlinks(parser.techniques)
            else:
                logger.error("You have not provided a valid markdown file path")
        else:
            logger.error("Provide a file path")
    elif args.generate_matrix:
        if args.path:
            parser = StixParser(config['repository-url'], domain, config.get('version'))
            logger.info("Extracting objects from STIX data")
            parser.get_data(techniques=True, tactics=True)

            if os.path.isfile(args.path):
                if args.path.endswith('.md'):
                    logger.info("Reading the Markdown note")
                    markdown_reader = MarkdownReader(args.path)
                    found_techniques = markdown_reader.find_techniques()
                    canvas_path = re.sub('.md$',"",args.path)
                else:
                    logger.error("You must provide a path to a .md file")
                    exit(-1)
            else:
                logger.warning("You have not provided a valid markdown file path. The full matrix will be generated.")
                found_techniques = []
                canvas_path = args.path

            markdown_generator = MarkdownGenerator(techniques=parser.techniques, tactics=parser.tactics)
            markdown_generator.create_canvas(canvas_path, found_techniques)
        else:
            logger.error("You must provide a valid file path")
            exit(-1)
    else:
        if args.output:
            if os.path.isdir(args.output):
                output_dir = args.output
            else:
                logger.warning("You have not provided an existing vault. Creating a new directory...")
                os.mkdir(args.output)
                output_dir = args.output
        else:
            logger.error("You have not provided a valid output directory")
            exit(-1)
    
        parser = StixParser(config['repository-url'], domain, config.get('version'))
        logger.info("Extracting objects from STIX data")
        parser.get_data(tactics=True, techniques=True, mitigations=True, groups=True, software=True)
        os.chdir(os.path.dirname(os.path.abspath(__file__)))

        markdown_generator = MarkdownGenerator(output_dir, parser.tactics, parser.techniques, parser.mitigations, parser.groups, parser.software)
        if config['mitre-object-types']['tactics']:
            logger.info("Creating Tactic notes")
            markdown_generator.create_tactic_notes()
        if config['mitre-object-types']['techniques']:
            logger.info("Creating Technique notes")
            markdown_generator.create_technique_notes()
        if config['mitre-object-types']['mitigations']:
            logger.info("Creating Mitigation notes")
            markdown_generator.create_mitigation_notes()
        if config['mitre-object-types']['groups']:
            logger.info("Creating Group notes")
            markdown_generator.create_group_notes()
        if config['mitre-object-types']['software']:
            logger.info("Creating Software notes")
            markdown_generator.create_software_notes()
        
        create_graph_json(output_dir)
