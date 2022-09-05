from parsers import vulnerability_parser, attack_graph_parser, topology_parser
from concurrent.futures import ProcessPoolExecutor
from mio import reader, writer
import networkx as nx
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


def add_node(config: dict, example_folder: str, networks: dict[str, dict[str, set]], services: dict[str, dict[str, ]],
             topology_graph: nx.Graph, gateway_graph: nx.Graph, gateway_nodes: set[str],
             attack_graph: dict[str, nx.DiGraph], executor: ProcessPoolExecutor,
             gateway_graph_labels: dict[(str, str), str], image: str, new_networks: list[str], name: str,
             vulnerabilities: dict[str, dict[str, ]], exploitable_vulnerabilities: dict[str, dict[str, dict[str, int]]],
             parsed_images: set[str]):
    
    new_service = {'image': image, 'networks': new_networks}
    
    topology_parser.add_service_networks(networks, gateway_nodes, new_service, name)
    services[name] = new_service
    
    topology_parser.add_service_to_graph(networks, topology_graph, gateway_graph,
                                         gateway_graph_labels, new_service, name)
    
    vulnerability_parser.add(config, services, vulnerabilities, exploitable_vulnerabilities,
                             parsed_images, example_folder, image)
    
    attack_graph_parser.\
        update_by_networks(networks, services, attack_graph,
                           exploitable_vulnerabilities, executor, new_service['networks'])
    
    print("Node added:", new_service)


def del_node(networks: dict[str, dict[str, set]], services: dict[str, dict[str, ]],
             topology_graph: nx.Graph, gateway_graph: nx.Graph,
             attack_graph: dict[str, nx.DiGraph], executor: ProcessPoolExecutor, affected_networks,
             gateway_nodes: set[str], gateway_graph_labels: dict[(str, str), str],
             exploitable_vulnerabilities: dict[str, dict[str, dict[str, int]]], name: str):
    
    topology_parser.delete(networks, services, topology_graph, gateway_graph, gateway_nodes, gateway_graph_labels, name)
    
    attack_graph_parser.\
        update_by_networks(networks, services, attack_graph, exploitable_vulnerabilities, executor, affected_networks)
    
    print("Node deleted: ", name)


def gen_defence_list(gateway_graph: nx.Graph, to: str) -> list[str, int]:
    # TODO
    path_counts = {}
    
    for path in nx.all_simple_paths(gateway_graph, 'outside', to):
        for node in path:
            path_counts[node]: int = path_counts.get(node, 0) + 1
    
    return sorted(path_counts.items())


def deploy_honeypot(config: dict, example_folder: str, networks: dict[str, dict[str, set]],
                    services: dict[str, dict[str, ]], topology_graph: nx.Graph, gateway_graph: nx.Graph,
                    gateway_nodes: set[str], gateway_graph_labels: dict[(str, str), str], new_networks: list[str],
                    attack_graph: dict[str, nx.DiGraph], executor: ProcessPoolExecutor,
                    vulnerabilities: dict[str, dict[str, ]],
                    exploitable_vulnerabilities: dict[str, dict[str, dict[str, int]]],
                    parsed_images: set[str], path_counts, minimum):
    h = 0
    
    for name in path_counts:
        if path_counts[name] < minimum:
            break
        honeypot_name = 'honey-' + str(h)
        networks[honeypot_name] = {'nodes': {name, honeypot_name}, 'gateways': {name}}
        image = 'nginx'
        
        add_node(config, example_folder, networks, services, topology_graph, gateway_graph, gateway_nodes, attack_graph,
                 executor, gateway_graph_labels, image, new_networks, name, vulnerabilities,
                 exploitable_vulnerabilities, parsed_images)
        
        h += 1


def visualise(topology_graph: nx.Graph, gateway_graph: nx.Graph, gateway_graph_labels: dict[(str, str), str],
              attack_graph: nx.DiGraph, result_folder: str, times: int):
    
    time_start = time.time()
    
    writer.write_topology_graph(topology_graph, result_folder, times)
    writer.write_attack_graph(attack_graph, result_folder, times)
    writer.write_gateway_graph(gateway_graph, gateway_graph_labels, result_folder, times)
    
    print("Time elapsed: " + str(time.time() - time_start) + " seconds.\n")
    
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
