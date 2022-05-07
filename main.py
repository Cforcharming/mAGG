#!/usr/bin/env python
"""Main module responsible for the attack graph generation pipeline."""

import os
import sys
import time
from graphviz import Digraph
from components import reader
from components import writer
from components import topology_parser
from components import attack_graph_parser
from components import vulnerability_parser

__version__ = "0.1-alpha"


def main(argv):
    """
    Main function responsible for running the attack graph generation pipeline.
    """
    
    # Checks if the command-line input and config file content is valid.
    reader.validate_command_line_input(argv)
    # Opening the configuration file.
    config = reader.validate_config_file()
    example_folder = argv[1]
    
    # Create folder where the result files will be stored.
    writer.create_folder(os.path.basename(example_folder))
    
    # Parsing the topology of the docker containers.
    time_start = time.time()
    topology = topology_parser.parse_topology(example_folder)
    duration_topology = time.time() - time_start
    print("Time elapsed: " + str(duration_topology) + " seconds.\n")
    
    # Visualizing the topology graph.
    duration_visualization = 0
    if config['generate_graphs']:
        time_start = time.time()
        topology_parser.create_topology_graph(topology,
                                              example_folder)
        duration_visualization = time.time() - time_start
        print("Time elapsed: " + str(duration_visualization) + " seconds.\n")
    
    # Parsing the vulnerabilities for each docker container.
    duration_vulnerabilities = 0
    if config["mode"] == "online":
        time_start = time.time()
        vulnerability_parser.parse_vulnerabilities(example_folder)
        duration_vulnerabilities = time.time() - time_start
        print("Time elapsed: " + str(duration_vulnerabilities) + " seconds.\n")
    
    vulnerabilities_folder_path = os.path.join(config['examples-results-path'],
                                               os.path.basename(example_folder))
    vulnerabilities = reader.read_vulnerabilities(vulnerabilities_folder_path, topology.keys())
    
    if not vulnerabilities.keys():
        print("There is a mistake with the vulnerabilities. Terminating the function...")
        return
    
    # Getting the attack graph nodes and edges from the attack paths.
    # Returns a tuple of the form:
    # (attack_graph_nodes, attack_graph_edges, duration_bdf, duration_vul_preprocessing)
    att_graph_tuple = attack_graph_parser.generate_attack_graph(config["attack-vector-folder-path"],
                                                                config["preconditions-rules"],
                                                                config["postconditions-rules"],
                                                                topology,
                                                                vulnerabilities,
                                                                example_folder)
    
    print("Time elapsed: " + str(att_graph_tuple[2] + att_graph_tuple[3]) + " seconds.\n")
    
    # Printing the graph properties.
    duration_graph_properties = attack_graph_parser.print_graph_properties(config["labels_edges"],
                                                                           nodes=att_graph_tuple[0],
                                                                           edges=att_graph_tuple[1])
    
    # print(att_graph_tuple[0])
    # print(len(att_graph_tuple[1].keys()))
    
    if config["show_one_vul_per_edge"]:
        for element in att_graph_tuple[1].keys():
            att_graph_tuple[1][element] = [att_graph_tuple[1][element][0]]
    
    # Visualizing the attack graph.
    if config['generate_graphs']:
        time_start = time.time()
        visualize_attack_graph(config["labels_edges"],
                               example_folder,
                               nodes=att_graph_tuple[0],
                               edges=att_graph_tuple[1])
        duration_visualization = time.time() - time_start
        print("Time elapsed: " + str(duration_visualization) + " seconds.\n")
    
    # Printing time summary of the attack graph generation.
    writer.print_summary(config["mode"],
                         config['generate_graphs'],
                         duration_topology=duration_topology,
                         duration_vulnerabilities=duration_vulnerabilities,
                         duration_bdf=att_graph_tuple[2],
                         duration_vuls_preprocessing=att_graph_tuple[3],
                         duration_graph_properties=duration_graph_properties,
                         duration_visualization=duration_visualization)
    
    return 0


def visualize_attack_graph(labels_edges,
                           example_folder_path,
                           nodes,
                           edges):
    """This function visualizes the attack graph with given counter examples."""
    
    dot = Digraph(comment="Attack Graph")
    for node in nodes:
        dot.node(node)
    
    for edge_name in edges.keys():
        terminal_points = edge_name.split("|")
        
        edge_vuls = edges[edge_name]
        
        if labels_edges == "single":
            for edge_vul in edge_vuls:
                dot.edge(terminal_points[0],
                         terminal_points[1],
                         label=edge_vul,
                         contstraint='false')
        
        elif labels_edges == "multiple":
            desc = ""
            for edge_vul in edge_vuls:
                if desc == "":
                    desc += edge_vul
                else:
                    desc += "\n" + edge_vul
            dot.edge(terminal_points[0],
                     terminal_points[1],
                     label=desc, contstraint='false')
    
    writer.write_attack_graph(example_folder_path, dot)
    print("Visualizing the graph...")


if __name__ == "__main__":
    exit(main(sys.argv))
