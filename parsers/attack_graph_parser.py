"""Module responsible for generating the attack graph."""

import time
import heapq
import networkx as nx
from queue import Queue
from concurrent.futures import ProcessPoolExecutor, Future, wait

from parsers import vulnerability_parser
from mio.wrapper import is_interactive


def generate_attack_graph(networks: dict[str, dict[str, set]], services: dict[str, dict[str, ]],
                          exploitable_vulnerabilities: dict[str, dict[str, dict[str, int]]],
                          executor: ProcessPoolExecutor) \
        -> (dict[str, nx.DiGraph], dict[str, dict[(str, str), str]], int):
    # TODO
    """Main pipeline for the attack graph generation algorithm."""
    
    print('Attack graphs of subnets generation started.')
    da = time.time()
    attack_graph: dict[str, nx.DiGraph] = dict()
    graph_labels: dict[str, dict[(str, str), str]] = dict()
    
    update_by_networks(networks, attack_graph, graph_labels, exploitable_vulnerabilities, executor, [*networks.keys()])
    
    print('Time for attack graphs of subnets generation:', time.time() - da, 'seconds.')
    return attack_graph, graph_labels, da


def get_graph_compose(attack_graph: dict[str, nx.DiGraph], graph_labels: dict[str, dict[(str, str), str]]) \
        -> (nx.DiGraph, dict[(str, str), str]):
    """This functions prints graph properties."""

    dcg = time.time()
    print('Composing attack graphs from subnets started.')
    
    composed_graph = nx.compose_all([*attack_graph.values()])
    composed_labels: dict[(str, str), str] = dict()
    
    for network in graph_labels:
        composed_labels |= graph_labels[network]
    
    dcg = time.time() - dcg
    print('Time for composing subnets:', dcg, 'seconds.')
    return composed_graph, composed_labels, dcg


def update_by_networks(networks: dict[str, dict[str, set]], attack_graph: dict[str, nx.DiGraph],
                       graph_labels: dict[str, dict[(str, str), str]],
                       exploitable_vulnerabilities: dict[str, dict[str, dict[str, int]]], executor: ProcessPoolExecutor,
                       affected_networks: list[str]):
    
    futures: list[Future] = list()
    
    for network in affected_networks:
        
        if not is_interactive():
            future = executor.submit(generate_sub_graph, networks, network, exploitable_vulnerabilities)
            future.add_done_callback(update(attack_graph, graph_labels, network))
            futures.append(future)
        else:
            sub_graph, sub_labels = generate_sub_graph(networks, network, exploitable_vulnerabilities)
            attack_graph[network] = sub_graph
            graph_labels[network] = sub_labels
    
    if not is_interactive():
        wait(futures)


def update(attack_graph: dict[str, nx.DiGraph], graph_labels: dict[str, dict[(str, str), str]], network: str):
    def cbs(future):
        sub_graph, sub_labels = future.result()
        attack_graph[network] = sub_graph
        graph_labels[network] = sub_labels
    return cbs


def generate_sub_graph(networks: dict[str, dict[str, set]], network: str,
                       exploitable_vulnerabilities: dict[str, dict[str, dict[str, int]]]) \
        -> (nx.DiGraph, dict[(str, str), str]):
    """Breadth first search approach for generation of nodes and edges
    without generating attack paths."""
    
    # TODO
    
    sub_graph = nx.DiGraph()
    sub_labels: dict[(str, str), str] = {}
    
    gateways: set[str] = networks[network]['gateways']
    neighbours: set[str] = networks[network]['nodes']
    for gateway in gateways:
        
        gateway_vulnerabilities = exploitable_vulnerabilities[gateway]['precond']
        for gateway_vulnerability in gateway_vulnerabilities:
            pre_condition = exploitable_vulnerabilities[gateway]['precond'][gateway_vulnerability]
            post_condition = exploitable_vulnerabilities[gateway]['postcond'][gateway_vulnerability]
            sub_graph.add_node((gateway, vulnerability_parser.get_privilege_level(pre_condition)))
        
        changed = True
        
        for neighbour in neighbours:
            current_states[neighbour] = -1
        current_states[gateway] = init_state
        while changed:
            changed = False
    
    edges = {}
    nodes = {}
    passed_nodes = {}
    passed_edges = {}
    
    # Putting the attacker in the queue
    queue = Queue()
    queue.put("outside|4")
    passed_nodes["outside|4"] = True
    
    while not queue.empty():
        
        parts_current = queue.get().split("|")
        current_node = parts_current[0]
        current_privilege = int(parts_current[1])
        
        neighbours = networks[current_node]['nodes']
        
        # Iterate through all of neighbours
        for neighbour in neighbours:
            
            # Checks if the attacker has access to the docker host.
            if neighbour != "outside":
                pre_conditions = exploitable_vulnerabilities[neighbour]["precond"]
                post_conditions = exploitable_vulnerabilities[neighbour]["postcond"]
                
                for vulnerability in pre_conditions.keys():
                    
                    if current_privilege >= pre_conditions[vulnerability] and \
                            ((neighbour != current_node and post_conditions[vulnerability] != 0) or
                             (neighbour == current_node and current_privilege < post_conditions[vulnerability])):
                        
                        # Add the edge
                        add_edge(nodes, edges, current_node,
                                 vulnerability_parser.get_privilege_level(current_privilege), neighbour,
                                 vulnerability_parser.get_privilege_level(post_conditions[vulnerability]),
                                 vulnerability, passed_edges)
                        
                        # If the neighbour was not passed, or it has a lower privilege...
                        passed_nodes_key = neighbour + "|" + str(post_conditions[vulnerability])
                        pn = passed_nodes.get(passed_nodes_key)
                        if pn is None or not pn:
                            # ... put it in the queue
                            queue.put(passed_nodes_key)
                            passed_nodes[passed_nodes_key] = True
    
    print('Generated sub attack graph for network', network)
    return sub_graph, sub_labels


def add_edge(nodes, edges, node_start, node_start_privilege, node_end, node_end_privilege, edge_desc, passed_edges):
    """
    Adding an edge to the attack graph and checking if nodes already exist.
    """
    
    # Checks if the opposite edge is already in the collection. If it is, don't add the edge.
    node_start_full = node_start + "(" + node_start_privilege + ")"
    node_end_full = node_end + "(" + node_end_privilege + ")"
    
    if passed_edges.get(node_end + "|" + node_start_full) is None:
        passed_edges[node_start + "|" + node_end_full] = True
    else:
        return
    
    if node_start_full not in nodes:
        nodes.add(node_start_full)
    
    if node_end_full not in nodes:
        nodes.add(node_end_full)
    
    key = node_start_full + "|" + node_end_full
    
    # if edge := edges.get(key) is None:
    edges[key] = [edge_desc]
    # elif edge_desc not in edge:
    #     edge.append(edge_desc)
