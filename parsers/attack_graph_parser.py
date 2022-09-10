"""Module responsible for generating the attack graph."""

import time
import math
import networkx as nx
from concurrent.futures import ProcessPoolExecutor, Future, wait
from parsers import vulnerability_parser


def generate_attack_graph(networks: dict[str, dict[str, set]], exploitable_vulnerabilities: dict[str, dict[str, dict]],
                          scores: dict[str, int], executor: ProcessPoolExecutor, single_exploit: bool) \
        -> (dict[str, nx.DiGraph], dict[str, dict[((str, str), (str, str)), str]], int):
    
    """Main pipeline for the attack graph generation algorithm."""
    
    print('Attack graphs of subnets generation started.')
    da = time.time()
    attack_graph: dict[str, nx.DiGraph] = dict()
    graph_labels: dict[str, dict[((str, str), (str, str)), str]] = dict()
    
    update_by_networks(networks, attack_graph, graph_labels, exploitable_vulnerabilities, scores, executor,
                       [*networks.keys()], single_exploit)
    
    print('Time for attack graphs of subnets generation:', time.time() - da, 'seconds.')
    return attack_graph, graph_labels, da


def get_graph_compose(attack_graph: dict[str, nx.DiGraph],
                      graph_labels: dict[str, dict[((str, str), (str, str)), str]]) \
        -> (nx.DiGraph, dict[((str, str), (str, str)), str]):
    """This functions prints graph properties."""

    dcg = time.time()
    print('Composing attack graphs from subnets started.')

    if 'full' not in attack_graph:
        
        composed_labels: dict[((str, str), (str, str)), str] = dict()
    
        try:
            composed_graph: nx.DiGraph = nx.compose_all([*attack_graph.values()])
            
            for network in graph_labels:
                composed_labels |= graph_labels[network]
        except ValueError:
            composed_graph = nx.DiGraph()
    
    else:
        composed_graph = attack_graph['full']
        composed_labels = graph_labels['full']
        
    dcg = time.time() - dcg
    print('Time for composing subnets:', dcg, 'seconds.')
    return composed_graph, composed_labels, dcg


# noinspection PyCallingNonCallable
def remove_redundant(composed_graph: nx.DiGraph, composed_labels: dict[((str, str), (str, str)), str]):
    depth_delete_stack = []
    
    for node in composed_graph:
        
        if composed_graph.in_degree(node) == 0:
            print(node)
            (name, privilege) = node
            if name != 'outside':
                depth_delete_stack.append(node)
    print(depth_delete_stack)
    
    while len(depth_delete_stack) > 0:
        depth_first_remove(composed_graph, composed_labels, depth_delete_stack)


def update_by_networks(networks: dict[str, dict[str, set]], attack_graph: dict[str, nx.DiGraph],
                       graph_labels: dict[str, dict[((str, str), (str, str)), str]],
                       exploitable_vulnerabilities: dict[str, dict[str, dict]], scores: dict[str, int],
                       executor: ProcessPoolExecutor, affected_networks: list[str], single_exploit: bool):
    
    futures: list[Future] = list()
    
    for network in affected_networks:
        
        future = executor.submit(generate_sub_graph, networks, network, exploitable_vulnerabilities, scores,
                                 single_exploit)
        future.add_done_callback(update(attack_graph, graph_labels, network))
        futures.append(future)

    wait(futures)


def update(attack_graph: dict[str, nx.DiGraph], graph_labels: dict[str, dict[((str, str), (str, str)), (str, str)]],
           network: str):
    def cbs(future):
        sub_graph, sub_labels = future.result()
        attack_graph[network] = sub_graph
        graph_labels[network] = sub_labels
    return cbs


def generate_sub_graph(networks: dict[str, dict[str, set]], network: str,
                       exploitable_vulnerabilities: dict[str, dict[str, dict]], scores: dict[str, int],
                       single_exploit: bool) \
        -> (nx.DiGraph, dict[((str, str), (str, str)), str]):
    """Breadth first search approach for generation of nodes and edges
    without generating attack paths."""
    
    sub_graph = nx.DiGraph()
    sub_labels: dict[((str, str), (str, str)), str] = {}
    
    gateways: set[str] = networks[network]['gateways']
    neighbours: set[str] = networks[network]['nodes']
    
    exploited_vulnerabilities: set[str] = set()
    
    for gateway in gateways:
        
        if gateway == 'outside':
            gateway_post_privileges = {4: ''}
        else:
            gateway_post_privileges: dict[int, str] = exploitable_vulnerabilities[gateway]['post']
        
        exploited_nodes: set[str] = {gateway}
        
        for current_privilege in gateway_post_privileges:
            depth_first_search(gateway, neighbours, current_privilege, exploited_nodes, exploited_vulnerabilities,
                               exploitable_vulnerabilities, scores, sub_graph, sub_labels, single_exploit)
    
    print('Generated sub attack graph for network', network, flush=True)
    return sub_graph, sub_labels


def depth_first_search(exploited_node: str, neighbours: set[str], current_privilege: int, exploited_nodes: set[str],
                       exploited_vulnerabilities: set[str], exploitable_vulnerabilities: dict[str, dict[str, dict]],
                       scores: dict[str, int], sub_graph: nx.DiGraph, sub_labels: dict[((str, str), (str, str)), str],
                       single_exploit: bool):
    
    for neighbour in neighbours:
        
        if neighbour == 'outside':
            continue
        
        for neighbour_pre_condition in range(0, current_privilege + 1):
            if len(exploitable_vulnerabilities[neighbour]['pre']) > 0:
                for vulnerability in exploitable_vulnerabilities[neighbour]['pre'][neighbour_pre_condition]:
                    neighbour_post_condition = exploitable_vulnerabilities[neighbour]['postcond'][vulnerability]
                    if vulnerability not in scores:
                        pass
                    
                    score = scores[vulnerability]
                    start_node = (exploited_node, vulnerability_parser.get_privilege_level(current_privilege))
                    end_node = (neighbour, vulnerability_parser.get_privilege_level(neighbour_post_condition))
                    
                    if single_exploit:
                        if neighbour not in exploited_nodes:
                            exploited_nodes.add(neighbour)
                            add_edge(sub_graph, sub_labels, start_node, end_node, vulnerability, score)
                            depth_first_search(neighbour, neighbours, neighbour_post_condition, exploited_nodes,
                                               exploited_vulnerabilities, exploitable_vulnerabilities, scores,
                                               sub_graph, sub_labels, single_exploit)
                    
                    else:
                        if (start_node, end_node) not in sub_labels \
                                 or vulnerability not in sub_labels[(start_node, end_node)]:
                            exploited_vulnerabilities.add(vulnerability)
                            add_edge(sub_graph, sub_labels, start_node, end_node, vulnerability, score)
                            depth_first_search(neighbour, neighbours, neighbour_post_condition, exploited_nodes,
                                               exploited_vulnerabilities, exploitable_vulnerabilities, scores,
                                               sub_graph, sub_labels, single_exploit)


def add_edge(sub_graph: nx.DiGraph, sub_labels: dict[((str, str), (str, str)), str], start_node: (str, str),
             end_node: (str, str), vulnerability: str, score: int):
    """
    Adding an edge to the attack graph.
    """
    
    weight = get_weight_from_score(score)
    
    sub_graph.add_edge(start_node, end_node, weight=weight)
    if (start_node, end_node) in sub_labels:
        sub_labels[(start_node, end_node)] += '\n' + vulnerability
    else:
        sub_labels[(start_node, end_node)] = vulnerability


def get_weight_from_score(score: int) -> float:
    weight = math.pow(10, -score)
    return weight


# noinspection PyCallingNonCallable
def depth_first_remove(composed_graph: nx.DiGraph, composed_labels: dict[((str, str), (str, str)), str],
                       depth_delete_stack: list[(str, str)]):

    node_to_remove = depth_delete_stack.pop()
    edges_to_remove = []
    end_nodes = set()
    
    out_edges = composed_graph.out_edges(node_to_remove)
    for out_edge in out_edges:
        (start_node, end_node) = out_edge
        edges_to_remove.append(out_edge)
        del composed_labels[out_edge]
        end_nodes.add(end_node)
    
    for end_node in end_nodes:
        
        if composed_graph.in_degree(end_node) == 0:
            depth_delete_stack.append(end_node)

    composed_graph.remove_node(node_to_remove)
