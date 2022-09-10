from concurrent.futures import ProcessPoolExecutor

import networkx as nx

from mio.wrapper import add_node
from layers import attack_graph_layer


def gen_defence_list(gateway_graph: nx.Graph, to: str, from_n='outside') -> list[str, int]:
    
    path_counts = {}
    
    for path in nx.all_simple_paths(gateway_graph, from_n, to):
        for node in path:
            if node in path_counts:
                path_counts[node] = path_counts[node] + 1
            else:
                path_counts[node] = 1
    
    return sorted(path_counts.items())


def deploy_honeypot(config: dict, example_folder: str, networks: dict[str, dict[str, set]],
                    services: dict[str, dict[str, ]], topology_graph: nx.Graph, gateway_graph: nx.Graph,
                    gateway_nodes: set[str], gateway_graph_labels: dict[(str, str), str], new_networks: list[str],
                    attack_graph: dict[str, nx.DiGraph], graph_labels: dict[str, dict[((str, str), (str, str)), str]],
                    executor: ProcessPoolExecutor, vulnerabilities: dict[str, dict[str, ]],
                    exploitable_vulnerabilities: dict[str, dict[str, dict]], scores: dict[str, int],
                    parsed_images: set[str], attack_vectors: dict[str, dict[str, ]], path_counts, minimum):
    h = 0
    
    affected_networks = []
    
    for name in path_counts:
        if path_counts[name] < minimum:
            break
        honeypot_name = 'honey-' + str(h)
        networks[honeypot_name] = {'nodes': {name, honeypot_name}, 'gateways': {name}}
        image = 'nginx'
        
        add_node(config, example_folder, networks, services, topology_graph, gateway_graph, gateway_nodes, attack_graph,
                 graph_labels, executor, gateway_graph_labels, image, new_networks, name, vulnerabilities,
                 exploitable_vulnerabilities, scores, attack_vectors, parsed_images)
        
        h += 1

    attack_graph_layer.update_by_networks(networks, attack_graph, graph_labels, exploitable_vulnerabilities, scores,
                                          executor, affected_networks, config['single-exploit-per-node'])
