# obsidian-mitre-attack

This repository implements a Python script that parses the MITRE ATT&CK knowledge base into a markdown format, making it readable and browsable using the Obsidian note-taking app. 
The ATT&CK data is retrieved from the MITRE GitHub repository (https://github.com/mitre-attack/attack-stix-data) that contains the dataset represented in STIX 2.1 JSON collection. The main idea behind this project is to make the MITRE ATT&CK knowledge base easily accessible and seamlessly integrable into Obsidian, along with reports or your personal notes. Utilizing Obsidian's features such as hyperlinks, tags, graph view, and more can greatly support threat intelligence analysis and investigations.

## Quick Start

### Installation

Clone this repository

```
git clone https://github.com/vincenzocaputo/obsidian-mitre-attack.git
```
Create a Python virtual environment

```
cd obsidian-mitre-attack
python3 -m venv venv
source venv/bin/activate
```

Install Python module dependencies
```
pip install -r requirements.txt
```

### Run

Run the application specifying the output directory path (i.e.: your obsidian vault)

```
python . -o obsidian_vault_path
```

### Options

```
usage: . [-h] [-d DOMAIN] [-o OUTPUT] [--generate-hyperlinks] [--generate-matrix] [--path PATH]

Downdload MITRE ATT&CK STIX data and parse it to Obsidian markdown notes

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'
  -o OUTPUT, --output OUTPUT
                        Output directory in which the notes will be saved. It should be placed inside a Obsidian
                        vault.
  --generate-hyperlinks
                        Generate techniques hyperlinks in a markdown note file
  --generate-matrix     Create ATT&CK matrix starting from a markdown note file
  --path PATH           Filepath to the markdown note file
```


## Images and Examples

![immagine](https://github.com/vincenzocaputo/obsidian-mitre-attack/assets/32276363/4612103a-2f25-4f6a-9a86-cf6bf9714334)
![immagine](https://github.com/vincenzocaputo/obsidian-mitre-attack/assets/32276363/edb1d85c-fa06-4ee1-9fe1-75d2a339fe9b)

![immagine](https://github.com/vincenzocaputo/obsidian-mitre-attack/assets/32276363/f667e05d-3939-4684-8731-8207c364b038)

![immagine](https://github.com/vincenzocaputo/obsidian-mitre-attack/assets/32276363/5311606f-7608-4e41-b9fb-fc9978d9b806)
