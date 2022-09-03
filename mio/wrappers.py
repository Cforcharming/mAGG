import networkx as nx

from parsers import vulnerability_parser, attack_graph_parser, topology_parser
from mio import reader, writer

import networkx
import time
import os


def init(argv):
    times = 0
    
    # Checks if the command-line input and config file content is valid.
    stat = reader.validate_command_line_input(argv)
    if stat != 0:
        return stat, None, None, None, None
    
    # Opening the configuration file.
    stat, config = reader.validate_config_file()
    if stat != 0:
        return stat, None, None, None, None
    
    # Create folder where the result files will be stored.
    example_folder = os.path.join(os.getcwd(), argv[1])
    result_folder = create_result_folder(os.path.basename(example_folder), config)
    
    return stat, config, example_folder, result_folder, times


def create_result_folder(example_folder, config):
    return writer.create_result_folder(example_folder, config)


def add_node(name, image, network, vulnerabilities, parsed_images, example_folder, networks, topology, topology_graph,
             services, config, nodes, edges, passed_nodes, passed_edges,
             attack_graph):
    # TODO
    new_service = {'image': image, 'networks': [network]}
    
    vulnerability_parser.add(vulnerabilities, parsed_images, example_folder, image)
    
    topology_parser.add(networks, topology, topology_graph, services, new_service, name)
    
    exploitable_vulnerabilities, dvp = attack_graph_parser.get_exploitable_vulnerabilities(
        services, vulnerabilities, config["attack-vector-folder-path"], config["preconditions-rules"],
        config["postconditions-rules"])
    
    attack_graph_parser.add(nodes, edges, passed_nodes, passed_edges, topology, name, exploitable_vulnerabilities,
                            attack_graph)
    
    print("Node added")


def del_node(name, networks, topology, services, nodes, edges, passed_nodes, passed_edges, attack_graph):
    topology_parser.delete(networks, topology, services, name)
    # TODO
    attack_graph_parser.delete(name, nodes, edges, passed_nodes, passed_edges, attack_graph)
    
    print("Node deleted")


def gen_defence_list(attack_graph: networkx.DiGraph, to):
    # TODO
    path_counts = {}
    
    for path in networkx.all_simple_paths(attack_graph, 'outside', to):
        for node in path:
            path_counts[node]: int = path_counts.get(node, 0) + 1
    
    return sorted(path_counts.items())


def deploy_honeypot(path_counts, minimum, vulnerabilities, parsed_images, example_folder, networks, topology,
                    topology_graph, services, config, nodes, edges, passed_nodes,
                    passed_edges, attack_graph):
    # TODO
    h = 0
    
    for (k, v) in path_counts:
        if v < minimum:
            break
        honeypot_name = 'honey' + str(h)
        networks[honeypot_name] = [k]
        image = 'mysql'
        network = [honeypot_name]

        add_node(honeypot_name, image, network, vulnerabilities, parsed_images, example_folder, networks, topology,
                 topology_graph, services, config, nodes, edges, passed_nodes, passed_edges, attack_graph)
        h += 1


def visualise(topology_graph: nx.Graph, gateway_graph: nx.Graph, gateway_graph_labels: dict[(str, str), str],
              attack_graph: nx.DiGraph, result_folder: str, times: int):
    time_start = time.time()
    
    writer.write_topology_graph(topology_graph, result_folder, times)
    writer.write_attack_graph(attack_graph, result_folder, times)
    writer.write_gateway_graph(gateway_graph, gateway_graph_labels, result_folder, times)
    
    duration_visualization = time.time() - time_start
    print("Time elapsed: " + str(duration_visualization) + " seconds.\n")
    
    return times + 1


def print_summary(no_topology_nodes=0, no_topology_edges=0, no_attack_graph_nodes=0, no_attack_graph_edges=0):
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
    
    print("\n\n")
