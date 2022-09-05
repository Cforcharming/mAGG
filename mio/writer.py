"""This module is responsible for writing the outputs into files."""

import os
import networkx as nx
from matplotlib import pyplot as plt


def write_attack_graph(composed_graph: nx.DiGraph, composed_labels: dict[(str, str), str], result_folder: str, i: int):
    # TODO
    """Writes the attack graph onto a dot file."""

    attack_graph_folder = os.path.join(result_folder, str(i))
    
    if not os.path.exists(attack_graph_folder):
        os.makedirs(attack_graph_folder)

    attack_graph_path = os.path.join(attack_graph_folder, 'attack-graph.png')
    
    if not os.path.exists(attack_graph_path):
        
        plt.axis("off")
        pos = nx.spring_layout(composed_graph)
        nx.draw_networkx_nodes(composed_graph, pos)
        nx.draw_networkx_edges(composed_graph, pos)
        nx.draw_networkx_labels(composed_graph, pos, labels=composed_labels)
        plt.show()
        plt.savefig(attack_graph_folder, transparent=True)
    
    print('Attack graph is at:', attack_graph_path)


def write_topology_graph(topology_graph: nx.Graph, result_folder: str, i: int):
    """Writes the topology graph onto a dot file."""

    topology_graph_folder = os.path.join(result_folder, str(i))
    
    if not os.path.exists(topology_graph_folder):
        os.makedirs(topology_graph_folder)
    
    topology_graph_path = os.path.join(topology_graph_folder, 'topology-graph.png')
    
    if not os.path.exists(topology_graph_path):
        
        plt.axis("off")
        pos = nx.spring_layout(topology_graph)
        nx.draw_networkx_nodes(topology_graph, pos)
        nx.draw_networkx_edges(topology_graph, pos)
        nx.draw_networkx_labels(topology_graph, pos)
        plt.show()
        plt.savefig(topology_graph_path, transparent=True)
    
    print('Topology graph is at:', topology_graph_path)


def write_gateway_graph(gateway_graph: nx.Graph, gateway_graph_labels: dict[(str, str), str],
                        result_folder: str, i: int):
    # TODO
    
    gateway_graph_folder = os.path.join(result_folder, str(i))
    if not os.path.exists(gateway_graph_folder):
        os.makedirs(gateway_graph_folder)
        
    gateway_graph_path = os.path.join(gateway_graph_folder, 'gateway-graph.png')
    
    if not os.path.exists(gateway_graph_path):
        
        plt.axis("off")
        pos = nx.spring_layout(gateway_graph)
        nx.draw_networkx_nodes(gateway_graph, pos)
        nx.draw_networkx_edges(gateway_graph, pos)
        nx.draw_networkx_labels(gateway_graph, pos)
        nx.draw_networkx_edge_labels(gateway_graph, pos, edge_labels=gateway_graph_labels)
        plt.show()
        plt.savefig(gateway_graph_path, transparent=True)
        
    print('Gateway graph is at:', gateway_graph_path)


def create_result_folder(example_folder, config):
    """Creates folder for storing the intermediate results of the examples."""
    
    result_folder = os.path.join(os.getcwd(), config["examples-results-path"], example_folder)
    if not os.path.exists(result_folder):
        os.makedirs(result_folder)
    
    return result_folder
