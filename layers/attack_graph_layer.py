"""Module responsible for generating the attack graph."""

import time
import math
import networkx as nx
from concurrent.futures import ProcessPoolExecutor, Future, wait

import vulnerability_layer


def generate_attack_graph(networks: dict[str, dict[str, set]], services: dict[str, dict[str]],
                          exploitable_vulnerabilities: dict[str, dict[str, dict]],
                          scores: dict[str, int], executor: ProcessPoolExecutor,
                          single_exploit: bool, single_label: bool) \
        -> (dict[str, nx.DiGraph], dict[str, dict[((str, str), (str, str)), str]], int):
    
    """Main pipeline for the attack graph generation algorithm."""
    
    print('Attack graphs of subnets generation started.')
    start = time.time()
    attack_graph: dict[str, nx.DiGraph] = dict()
    graph_labels: dict[str, dict[((str, str), (str, str)), str]] = dict()
    
    update_by_networks(networks, attack_graph, graph_labels, services, exploitable_vulnerabilities, scores, executor,
                       [*networks.keys()], single_exploit, single_label)
    
    da = time.time() - start
    print('Time for attack graphs of subnets generation:', da, 'seconds.')
    return attack_graph, graph_labels, da


def get_graph_compose(attack_graph: dict[str, nx.DiGraph],
                      graph_labels: dict[str, dict[((str, str), (str, str)), str]]) \
        -> (nx.DiGraph, dict[((str, str), (str, str)), str]):
    """This functions prints graph properties."""

    dcg = time.time()
    print('Composing attack graphs from subnets started.')
    
    composed_graph = nx.compose_all([*attack_graph.values()])
    composed_labels: dict[((str, str), (str, str)), str] = dict()
    
    for network in graph_labels:
        composed_labels |= graph_labels[network]
    
    dcg = time.time() - dcg
    print('Time for composing subnets:', dcg, 'seconds.')
    return composed_graph, composed_labels, dcg


def update_by_networks(networks: dict[str, dict[str, set]], attack_graph: dict[str, nx.DiGraph],
                       graph_labels: dict[str, dict[((str, str), (str, str)), str]], services: dict[str, dict[str]],
                       exploitable_vulnerabilities: dict[str, dict[str, dict]], scores: dict[str, int],
                       executor: ProcessPoolExecutor, affected_networks: list[str],
                       single_exploit: bool, single_label: bool):
    
    futures: list[Future] = list()

    if executor is not None:
        for network in affected_networks:
            future = executor.submit(generate_sub_graph, services, networks, network, exploitable_vulnerabilities,
                                     scores, single_exploit, single_label)
            future.add_done_callback(update(attack_graph, graph_labels, network))
            futures.append(future)
    
    elif 'exposed' in affected_networks:
        composed_graph, composed_labels = generate_full_from_exposed(services, exploitable_vulnerabilities, networks,
                                                                     scores, single_exploit, single_label)
        attack_graph['full'] = composed_graph
        graph_labels['full'] = composed_labels
    
    else:
        for network in affected_networks:
            sub_graph, sub_labels = \
                generate_sub_graph(services, networks, network, exploitable_vulnerabilities, scores,
                                   single_exploit, single_label)
            attack_graph[network] = sub_graph
            graph_labels[network] = sub_labels

    if executor is not None:
        wait(futures)


def update(attack_graph: dict[str, nx.DiGraph], graph_labels: dict[str, dict[((str, str), (str, str)), (str, str)]],
           network: str):
    def cbs(future):
        sub_graph, sub_labels = future.result()
        attack_graph[network] = sub_graph
        graph_labels[network] = sub_labels
    return cbs


def generate_sub_graph(services: dict[str, dict[str]], networks: dict[str, dict[str, set]], network: str,
                       exploitable_vulnerabilities: dict[str, dict[str, dict]], scores: dict[str, int],
                       single_exploit: bool, single_label: bool) \
        -> (nx.DiGraph, dict[((str, str), (str, str)), str]):
    """Breadth first search approach for generation of sub graphs."""
    
    sub_graph = nx.DiGraph()
    sub_labels: dict[((str, str), (str, str)), str] = {}
    
    gateways: set[str] = networks[network]['gateways']
    neighbours: set[str] = networks[network]['nodes']
    
    exploited_vulnerabilities: set[str] = set()
    
    for gateway in gateways:
        
        if gateway == 'outside':
            gateway_post_privileges = {4: ['']}
        else:
            gateway_post_privileges: dict[int, list[str]] = exploitable_vulnerabilities[gateway]['post']
        
        depth_stack: list[(str, int)] = list()
        exploited_nodes: set[str] = {gateway}
        
        for current_privilege in gateway_post_privileges:
            depth_stack.append((gateway, current_privilege))
            
        while len(depth_stack) > 0:
            depth_first_search(exploited_nodes, exploited_vulnerabilities, services, networks,
                               exploitable_vulnerabilities, scores, sub_graph, sub_labels, depth_stack,
                               single_exploit, single_label, neighbours)
    
    print('Generated sub attack graph for network', network, flush=True)
    return sub_graph, sub_labels


def generate_full_from_exposed(services: dict[str, dict[str]], exploitable_vulnerabilities: dict[str, dict[str, dict]],
                               networks: dict[str, dict[str, set]], scores: dict[str, int],
                               single_exploit: bool, single_label: bool) \
        -> (nx.DiGraph, dict[((str, str), (str, str)), str]):
    
    composed_graph = nx.DiGraph()
    composed_labels: dict[((str, str), (str, str)), str] = {}
    
    exploited_vulnerabilities: set[str] = set()
    depth_stack: list[(str, int)] = [('outside', 4)]
    exploited_nodes: set[str] = {'outside'}

    while len(depth_stack) > 0:
        depth_first_search(exploited_nodes, exploited_vulnerabilities, services, networks, exploitable_vulnerabilities,
                           scores, composed_graph, composed_labels, depth_stack, single_exploit, single_label)
    
    print('Generated full attack graph from outside.', flush=True)
    return composed_graph, composed_labels
    

def get_neighbours(services: dict[str, dict[str]], networks: dict[str, dict[str, set]], node: str) -> set[str]:
    
    neighbours: set[str] = set()
    if node != 'outside':
        nws = services[node]['networks']
    else:
        nws = ['exposed']
    
    for nw in nws:
        for neighbour in networks[nw]['nodes']:
            neighbours.add(neighbour)
    
    return neighbours


def depth_first_search(exploited_nodes: set[str], exploited_vulnerabilities: set[str], services: dict[str, dict[str]],
                       networks: dict[str, dict[str, set]], exploitable_vulnerabilities: dict[str, dict[str, dict]],
                       scores: dict[str, int], sub_graph: nx.DiGraph, sub_labels: dict[((str, str), (str, str)), str],
                       depth_stack: list[(str, int)], single_exploit: bool, single_label: bool, neighbours=None):
    
    (exploited_node, current_privilege) = depth_stack.pop()
    
    if neighbours is None:
        neighbours = get_neighbours(services, networks, exploited_node)
    
    for neighbour in neighbours:
        
        if neighbour == 'outside':
            continue
        
        neighbour_exploitable = exploitable_vulnerabilities[neighbour]['pre']
        neighbour_post = exploitable_vulnerabilities[neighbour]['postcond']
        
        for neighbour_pre_condition in range(0, current_privilege + 1):
            for vulnerability in neighbour_exploitable[neighbour_pre_condition]:
                
                neighbour_post_condition = neighbour_post[vulnerability]
                score = scores[vulnerability]
                start_node = (exploited_node, vulnerability_parser.get_privilege_level(current_privilege))
                end_node = (neighbour, vulnerability_parser.get_privilege_level(neighbour_post_condition))
                
                if single_exploit:
                    if neighbour not in exploited_nodes:
                        exploited_nodes.add(neighbour)
                        add_edge(sub_graph, sub_labels, start_node, end_node, vulnerability, score)
                        depth_stack.append((neighbour, neighbour_pre_condition))
                
                else:
                    if (start_node, end_node) not in sub_labels \
                             or (not single_label and vulnerability not in sub_labels[(start_node, end_node)]):
                        exploited_vulnerabilities.add(vulnerability)
                        add_edge(sub_graph, sub_labels, start_node, end_node, vulnerability, score)
                        depth_stack.append((neighbour, neighbour_pre_condition))


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