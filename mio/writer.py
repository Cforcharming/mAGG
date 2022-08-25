#!/usr/bin/env python
"""This module is responsible for writing the outputs into files."""

import os
import json
from graphviz import Digraph


def write_topology(topology, result_folder, i):
    """Writes list of services into a file."""
    
    topology_writing_path = os.path.join(result_folder, 'topology', str(i) + "-topology.json")
    
    if not os.path.exists(topology_writing_path):
        with open(topology_writing_path, "w") as topology_file:
            json.dump(topology, topology_file)


def write_attack_graph(labels_edges, nodes, edges, result_folder, i):
    """Writes the attack graph onto a dot file."""
    
    attack_graph_path = os.path.join(result_folder, 'attack_graph', str(i) + "-attack_graph.dot")
    
    if not os.path.exists(attack_graph_path):
        attack_dot = Digraph(comment="Attack Graph", format='png')
        for node in nodes:
            attack_dot.node(node)
        
        for edge_name in edges.keys():
            terminal_points = edge_name.split("|")
        
            edge_vulnerabilities = edges[edge_name]
        
            if labels_edges == "single":
                for edge_vulnerability in edge_vulnerabilities:
                    attack_dot.\
                        edge(terminal_points[0], terminal_points[1], label=edge_vulnerability, contstraint='false')
        
            elif labels_edges == "multiple":
                descriptions = ""
                for edge_vulnerability in edge_vulnerabilities:
                    if descriptions == "":
                        descriptions += edge_vulnerability
                    else:
                        descriptions += "\n" + edge_vulnerability
                attack_dot.edge(terminal_points[0], terminal_points[1], label=descriptions, contstraint='false')
        
        attack_dot.render(attack_graph_path)
    print("Attack graph is at: " + attack_graph_path + ".png")


def write_topology_graph(topology_graph, result_folder, i):
    """Writes the topology graph onto a dot file."""
    
    topology_graph_path = os.path.join(result_folder, 'topology_graph', str(i) + "-topology_graph.dot")
    
    if not os.path.exists(topology_graph_path):
        topology_graph.render(topology_graph_path)
    print("Topology graph is at: " + topology_graph_path + ".png")


def copy_vulnerability_file(clairctl_home, image_name, example_folder):
    """Copies the vulnerability file from clairctl to the local location."""

    json_name = os.path.join(example_folder, image_name + "-vulnerabilities.json")
    
    os.rename(os.path.join(clairctl_home, "docker-compose-data", "clairctl-reports", "json", "analysis-" + image_name
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


def print_summary(config_generate_graphs, no_topology_nodes=0, no_topology_edges=0, no_attack_graph_nodes=0,
                  no_attack_graph_edges=0, duration_topology=0, duration_vulnerabilities=0,
                  duration_vulnerabilities_preprocessing=0, duration_bdf=0, duration_graph_properties=0,
                  duration_visualization=0, duration_total_time=0):
    """Function responsible for printing the time and properties summary."""
    
    if no_topology_nodes != 0 and no_topology_edges != 0 and no_attack_graph_nodes != 0 and no_attack_graph_edges != 0:
        print("\n**********Nodes and edges summary of the topology and attack graphs**********")
    
    if no_topology_nodes != 0:
        print("The number of nodes in the topology graph is " + str(no_topology_nodes) + ".")
    
    if no_topology_edges != 0:
        print("The number of edges in the topology graph is " + str(no_topology_edges) + ".")
    
    if no_attack_graph_nodes != 0:
        print("The number of nodes in the attack graph is " + str(no_attack_graph_nodes) + ".")
    
    if no_attack_graph_edges != 0:
        print("The number of edges in the attack graph is " + str(no_attack_graph_edges) + ".")
    
    print("\n**********Time Summary of the Attack Graph Generation Process**********")
    
    print("Topology parsing took " + str(duration_topology) + " seconds.")
    
    print("The attack graph generation took " +
          str(duration_vulnerabilities_preprocessing + duration_bdf) + " seconds.")
    
    print("	-Preprocessing of the vulnerabilities took " +
          str(duration_vulnerabilities) + " seconds.")
    
    print("	-Breadth First Search took " + str(duration_bdf) + " seconds.")
    
    if duration_graph_properties != 0:
        print("Calculation of Graph Properties took " + str(duration_graph_properties) + " seconds.")
    
    if config_generate_graphs:
        print("Attack Graph Visualization took " + str(duration_visualization) + " seconds.")
    
    if duration_total_time != 0:
        print("The total elapsed time is " + str(duration_total_time) + " seconds.")
    print("\n\n")
