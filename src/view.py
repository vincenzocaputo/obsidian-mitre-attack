from . import ROOT
import os
import shutil

def create_graph_json(output_dir):
    obsidian_settings_dir = os.path.join(output_dir, '.obsidian')
    graph_json_file = os.path.join(obsidian_settings_dir, 'graph.json')
    
    local_graph_json_file = os.path.join(ROOT, 'res/graph.json')

    if not os.path.exists(obsidian_settings_dir):
        os.mkdir(obsidian_settings_dir)
    shutil.copyfile(local_graph_json_file, graph_json_file)
