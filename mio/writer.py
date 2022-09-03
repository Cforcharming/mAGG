"""This module is responsible for writing the outputs into files."""

import os
import shutil
import networkx as nx


def write_attack_graph(attack_graph: nx.DiGraph, result_folder: str, i: int):
    # TODO
    """Writes the attack graph onto a dot file."""
    
    attack_graph_path = os.path.join(result_folder, 'attack_graph', str(i) + "-attack_graph.dot")
    
    if not os.path.exists(attack_graph_path):
        pass
    
    print("Attack graph is at: " + attack_graph_path + ".png")


def write_topology_graph(topology_graph: nx.Graph, result_folder: str, i: int):
    # TODO
    """Writes the topology graph onto a dot file."""
    
    topology_graph_path = os.path.join(result_folder, 'topology_graph', str(i) + "-topology_graph.dot")
    
    if not os.path.exists(topology_graph_path):
        pass
    print("Topology graph is at: " + topology_graph_path + ".png")


def write_gateway_graph(gateway_graph: nx.Graph, gateway_graph_labels: dict[(str, str), str],
                        result_folder: str, i: int):
    # TODO
    
    topology_graph_path = os.path.join(result_folder, 'topology_graph', str(i) + "-topology_graph.dot")
    
    if not os.path.exists(topology_graph_path):
        pass
    print("Topology graph is at: " + topology_graph_path + ".png")


def copy_vulnerability_file(clairctl_home, image_name, example_folder):
    """Copies the vulnerability file from clairctl to the local location."""
    
    json_name = os.path.join(example_folder, image_name + "-vulnerabilities.json")
    
    shutil.copy(os.path.join(clairctl_home, "docker-compose-data", "clairctl-reports", "json", "analysis-" + image_name
                             + "-latest.json"), json_name)


def create_result_folder(example_folder, config):
    """Creates folder for storing the intermediate results of the examples."""
    
    result_folder = os.path.join(os.getcwd(), config["examples-results-path"], example_folder)
    if not os.path.exists(result_folder):
        os.makedirs(result_folder)
    
    topology_writing_path = os.path.join(result_folder, 'topology')
    if not os.path.exists(topology_writing_path):
        os.makedirs(topology_writing_path)
    
    attack_graph_path = os.path.join(result_folder, 'attack_graph')
    if not os.path.exists(attack_graph_path):
        os.makedirs(attack_graph_path)
    
    topology_graph_path = os.path.join(result_folder, 'topology_graph')
    if not os.path.exists(topology_graph_path):
        os.makedirs(topology_graph_path)
    
    return result_folder
