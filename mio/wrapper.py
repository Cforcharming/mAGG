from layers import vulnerability_layer
from concurrent.futures import ProcessPoolExecutor
from mio import reader, writer
import networkx as nx
import time
import os


def init(argv: list) -> (int, dict, list[str], int):
    times = 0

    # Opening the configuration file.
    stat, config = reader.validate_config_file()
    if stat != 0:
        return stat, None, None, None, None
    
    # Checks if the command-line input and config file content is valid.
    stat, examples = reader.validate_command_line_input(argv, config)
    if stat != 0:
        return stat, None, None, None, None
    
    return stat, config, examples, times


def create_folders(example_basename: str, config: dict) -> (str, str):

    # Create folder where the result files will be stored.
    example_folder = os.path.join(os.getcwd(), config['examples-path'], example_basename)
    result_folder = writer.create_result_folder(example_basename, config)
    
    return example_folder, result_folder


def add_node(config: dict, example_folder: str, networks: dict[str, dict[str, set]], services: dict[str, dict[str, ]],
             topology_graph: nx.Graph, gateway_graph: nx.Graph, gateway_nodes: set[str],
             attack_graph: dict[str, nx.DiGraph], graph_labels: dict[str, dict[((str, str), (str, str)), str]],
             executor: ProcessPoolExecutor, gateway_graph_labels: dict[(str, str), str],
             image: str, new_networks: list[str], name: str, vulnerabilities: dict[str, dict[str, ]],
             exploitable_vulnerabilities: dict[str, dict[str, dict]], scores: dict[str, int],
             attack_vectors: dict[str, dict[str, ]], parsed_images: set[str]):
    
    new_service = {'image': image, 'networks': new_networks}
    
    topology_parser.add_service_networks(networks, gateway_nodes, new_service, name)
    services[name] = new_service
    
    topology_parser.add_service_to_graph(networks, topology_graph, gateway_graph,
                                         gateway_graph_labels, new_service, name)
    
    vulnerability_parser.add(config, services, vulnerabilities, attack_vectors, exploitable_vulnerabilities, scores,
                             parsed_images, example_folder, image, config['single-edge-label'])

    attack_graph_parser.update_by_networks(networks, attack_graph, graph_labels, exploitable_vulnerabilities, scores,
                                           executor, new_networks, config['single-exploit-per-node'])
    
    print("Node added:", new_service)


def del_node(networks: dict[str, dict[str, set]], services: dict[str, dict[str, ]], topology_graph: nx.Graph,
             gateway_graph: nx.Graph, attack_graph: dict[str, nx.DiGraph], config: dict,
             graph_labels: dict[str, dict[((str, str), (str, str)), str]], executor: ProcessPoolExecutor,
             affected_networks, gateway_nodes: set[str], gateway_graph_labels: dict[(str, str), str],
             exploitable_vulnerabilities: dict[str, dict[str, dict]], scores: dict[str, int], name: str):
    
    topology_parser.delete(networks, services, topology_graph, gateway_graph, gateway_nodes, gateway_graph_labels, name)

    attack_graph_parser. \
        update_by_networks(networks, attack_graph, graph_labels, exploitable_vulnerabilities, scores, executor,
                           affected_networks, config['single-exploit-per-node'])
    
    print("Node deleted: ", name)


def visualise(topology_graph: nx.Graph, gateway_graph: nx.Graph, gateway_graph_labels: dict[(str, str), str],
              attack_graph: nx.DiGraph, composed_labels: dict[((str, str), (str, str)), str], result_folder: str,
              times: int):
    
    time_start = time.time()
    
    writer.write_topology_graph(topology_graph, result_folder, times)
    writer.write_attack_graph(attack_graph, composed_labels, result_folder, times)
    writer.write_gateway_graph(gateway_graph, gateway_graph_labels, result_folder, times)
    
    print('Time for visualising:', time.time() - time_start, 'seconds.')


def print_summary(topology_nodes, topology_edges, attack_graph_nodes, attack_graph_edges):
    """Function responsible for printing the time and properties summary."""
    
    print('The number of nodes in the topology graph is', topology_nodes)
    print('The number of edges in the topology graph is', topology_edges)
    print('The number of nodes in the attack graph is', attack_graph_nodes)
    print('The number of edges in the attack graph is', attack_graph_edges, end='\n\n\n')
