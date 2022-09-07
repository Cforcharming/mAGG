"""Module responsible for generating the attack graph."""

import time
import heapq
import networkx as nx
from queue import Queue
from concurrent.futures import ProcessPoolExecutor, Future, wait

from parsers import vulnerability_parser
from mio import wrapper


def generate_attack_graph(networks: dict[str, dict[str, set]], exploitable_vulnerabilities: dict[str, dict[str, dict]],
                          scores: dict[str, int], executor: ProcessPoolExecutor) \
        -> (dict[str, nx.DiGraph], dict[str, dict[((str, str), (str, str)), (str, str)]], int):
    # TODO
    """Main pipeline for the attack graph generation algorithm."""
    
    print('Attack graphs of subnets generation started.')
    da = time.time()
    attack_graph: dict[str, nx.DiGraph] = dict()
    graph_labels: dict[str, dict[((str, str), (str, str)), (str, str)]] = dict()
    
    update_by_networks(networks, attack_graph, graph_labels, exploitable_vulnerabilities, scores, executor,
                       [*networks.keys()])
    
    print('Time for attack graphs of subnets generation:', time.time() - da, 'seconds.')
    return attack_graph, graph_labels, da


def get_graph_compose(attack_graph: dict[str, nx.DiGraph],
                      graph_labels: dict[str, dict[((str, str), (str, str)), (str, str)]]) \
        -> (nx.DiGraph, dict[((str, str), (str, str)), (str, str)]):
    """This functions prints graph properties."""

    dcg = time.time()
    print('Composing attack graphs from subnets started.')
    
    composed_graph = nx.compose_all([*attack_graph.values()])
    composed_labels: dict[((str, str), (str, str)), (str, str)] = dict()
    
    for network in graph_labels:
        composed_labels |= graph_labels[network]
    
    dcg = time.time() - dcg
    print('Time for composing subnets:', dcg, 'seconds.')
    return composed_graph, composed_labels, dcg


def update_by_networks(networks: dict[str, dict[str, set]], attack_graph: dict[str, nx.DiGraph],
                       graph_labels: dict[str, dict[((str, str), (str, str)), (str, str)]],
                       exploitable_vulnerabilities: dict[str, dict[str, dict]], scores: dict[str, int],
                       executor: ProcessPoolExecutor, affected_networks: list[str]):
    
    futures: list[Future] = list()
    
    for network in affected_networks:
        
        if not wrapper.is_interactive():
            future = executor.submit(generate_sub_graph, networks, network, exploitable_vulnerabilities, scores)
            future.add_done_callback(update(attack_graph, graph_labels, network))
            futures.append(future)
        else:
            sub_graph, sub_labels = generate_sub_graph(networks, network, exploitable_vulnerabilities, scores)
            attack_graph[network] = sub_graph
            graph_labels[network] = sub_labels
    
    if not wrapper.is_interactive():
        wait(futures)


def update(attack_graph: dict[str, nx.DiGraph], graph_labels: dict[str, dict[((str, str), (str, str)), (str, str)]],
           network: str):
    def cbs(future):
        sub_graph, sub_labels = future.result()
        attack_graph[network] = sub_graph
        graph_labels[network] = sub_labels
    return cbs


def generate_sub_graph(networks: dict[str, dict[str, set]], network: str,
                       exploitable_vulnerabilities: dict[str, dict[str, dict]], scores: dict[str, int]) \
        -> (nx.DiGraph, dict[((str, str), (str, str)), (str, str)]):
    """Breadth first search approach for generation of nodes and edges
    without generating attack paths."""
    
    # TODO
    
    sub_graph = nx.DiGraph()
    sub_labels: dict[((str, str), (str, str)), (str, str)] = {}
    
    gateways: set[str] = networks[network]['gateways']
    neighbours: set[str] = networks[network]['nodes']
    for gateway in gateways:
        
        gateway_post_privileges: dict[int, str] = exploitable_vulnerabilities[gateway]['post']
        
        for current_privilege in gateway_post_privileges:
            for neighbour in neighbours:
                for neighbour_pre_condition in range(0, current_privilege + 1):
                    if len(exploitable_vulnerabilities[neighbour]['pre']) > 0:
                        for vulnerability in exploitable_vulnerabilities[neighbour]['pre'][neighbour_pre_condition]:
                            neighbour_post_condition = exploitable_vulnerabilities[neighbour]['postcond'][vulnerability]
                            add_edge(sub_graph, sub_labels, gateway, current_privilege, neighbour, neighbour_post_condition, vulnerability)
    
    print('Generated sub attack graph for network', network)
    return sub_graph, sub_labels


def add_edge(sub_graph: nx.DiGraph, sub_labels: dict[((str, str), (str, str)), (str, str)], n1: str, pre: int, n2: str,
             post: int, vulnerability: str):
    """
    Adding an edge to the attack graph.
    """
    # TODO
