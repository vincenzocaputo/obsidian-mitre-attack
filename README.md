# obsidian-mitre-attack

This repository implements a Python script that parses the MITRE ATT&CK knowledge base into a markdown format, making it readable and browsable using the Obsidian note-taking app. 
The ATT&CK data is retrieved from the MITRE GitHub repository (https://github.com/mitre-attack/attack-stix-data) that contains the dataset represented in STIX 2.1 JSON collection. 

The main idea behind this project is to make the MITRE ATT&CK knowledge base easily accessible and seamlessly integrable into Obsidian, along with reports or your personal notes. Utilizing Obsidian's features such as hyperlinks, tags, graph view, and more can greatly support threat intelligence analysis and investigations.

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

#### Edit the config file (Optional)

> **It is recommended to use the default config file.**


In the `config.yml` file, you can change the following options:

- **repository-url**: The base URL pointing to the mitre/attack-stix-data repository. You can define also a local file path or other URLs. However, remember that this project is intended to parse data from the MITRE ATT&CK framework. Providing different JSON files may break the script execution.
- **version**: The ATT&CK version to pull. You can remove this entry to pull the latest version. Please note that newer versions may not have been tested and some errors may occur. In case of an error, do not hesitate to open a problem.
- **mitre-object-types**: This option lists all the type of MITRE objects that are parsed by the script. You can set to `false` the options corresponding to the types of objects for which you don't want to create markdown notes in your vault.


#### Run the script
Run the application specifying the output directory path (i.e.: your obsidian vault)

```
python run.py -o obsidian_vault_path
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

![immagine](https://github.com/vincenzocaputo/obsidian-mitre-attack/assets/32276363/f9e3aa4d-fdae-44b7-9036-616ed9f61d69)

![immagine](https://github.com/vincenzocaputo/obsidian-mitre-attack/assets/32276363/67b600e4-9928-494e-ac55-bd1e2e2f1ddd)

![immagine](https://github.com/vincenzocaputo/obsidian-mitre-attack/assets/32276363/68edd2f7-4761-4696-9aa6-ad6c86bf153f)

![immagine](https://github.com/vincenzocaputo/obsidian-mitre-attack/assets/32276363/48e99e68-4d38-45f2-8255-c88648e8a5ce)



