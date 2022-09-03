#!/usr/bin/env python
"""Main module responsible for the attack graph generation pipeline."""

import os
import sys
import networkx as nx
from concurrent.futures import ProcessPoolExecutor

from parsers import vulnerability_parser, attack_graph_parser, topology_parser
from mio import wrappers

__version__ = "1.0-dev2"


def main(argv):
    """
    Main function responsible for running the attack graph generation pipeline.
    """
    
    stat, config, example_folder, result_folder, times = wrappers.init(argv)
    if stat != 0:
        return stat
    
    # Parsing the topology of the docker containers.
    networks, services, gateway_nodes = topology_parser.parse_topology(example_folder)

    networks: dict[str, dict[str, set]]
    services: dict[str, dict[str, ]]
    gateway_nodes: set[str]
    
    # Visualizing the topology graph.
    topology_graph, gateway_graph, gateway_graph_labels = topology_parser.create_graphs(networks, services)

    topology_graph: nx.Graph
    gateway_graph: nx.Graph
    gateway_graph_labels: dict[(str, str), str]
    
    # Parsing the vulnerabilities for each docker container.
    stat, vulnerabilities, parsed_images, duration_vulnerabilities = vulnerability_parser. \
        parse_vulnerabilities(example_folder, services)
    if stat != 0:
        return stat

    vulnerabilities: dict[str, dict[str, ]]
    parsed_images: set[str]
    
    # Merging the attack vector files and creating an attack vector dictionary.
    exploitable_vulnerabilities, dvp = attack_graph_parser.get_exploitable_vulnerabilities(
        services, vulnerabilities, config["attack-vector-folder-path"], config["preconditions-rules"],
        config["postconditions-rules"])

    exploitable_vulnerabilities: dict[str, dict[str, dict[str, int]]]
    
    # Getting the attack graph nodes and edges from the attack paths.
    
    executor = ProcessPoolExecutor()
    
    nodes, edges, passed_nodes, passed_edges, duration_bdf = attack_graph_parser.\
        generate_attack_graph(networks, services, gateway_graph, exploitable_vulnerabilities, executor)
    
    print("Time elapsed: " + str(duration_bdf + dvp) + " seconds.\n")
    
    duration_graph_properties, attack_graph = attack_graph_parser. \
        print_graph_properties(config["labels_edges"], nodes, edges)
    
    attack_graph: nx.DiGraph
    
    for element in edges.keys():
        edges[element] = [edges[element][0]]
    
    # Visualizing the attack graph.
    times = wrappers.visualise(topology_graph, gateway_graph, gateway_graph_labels, attack_graph, result_folder, times)
    
    example_folders = os.listdir(os.path.join(os.getcwd(), 'examples/full-conn'))
    
    for example_folder in example_folders:
        print('\n\n\n**************************' + example_folder + '**************************\n\n\n')
        example_folder = os.path.join(os.getcwd(), 'examples/full-conn', example_folder)
        # Create folder where the result files will be stored.
        result_folder = wrappers.create_result_folder(os.path.join('full-conn',
                                                                   os.path.basename(example_folder)), config)

        networks, services, gateway_nodes = topology_parser.parse_topology(example_folder)
        topology_graph, gateway_graph, gateway_graph_labels = topology_parser.create_graphs(networks, services)

        print("Start with attack graph generation...")
        nodes, edges, passed_nodes, passed_edges, duration_bdf = attack_graph_parser. \
            generate_attack_graph(networks, services, gateway_graph, exploitable_vulnerabilities, executor)

        print("Time elapsed: " + str(duration_bdf + dvp) + " seconds.\n")
        
        # duration_graph_properties, attack_graph = attack_graph_parser.\
        #     print_graph_properties(config["labels_edges"], nodes, edges)
        
        for element in edges.keys():
            edges[element] = [edges[element][0]]
        
        # Visualizing the attack graph.
        # times = visualise(topology, result_folder, times, config['labels_edges'], nodes, edges)
        
        # Printing time summary of the attack graph generation.
        wrappers.print_summary(topology_graph.number_of_nodes(),
                               topology_graph.number_of_edges(),
                               attack_graph.number_of_nodes(),
                               attack_graph.number_of_edges())


if __name__ == "__main__":
    exit(main(sys.argv))
