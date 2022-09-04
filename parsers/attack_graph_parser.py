"""Module responsible for generating the attack graph."""

import time
import networkx as nx
from queue import Queue
from parsers import vulnerability_parser
from concurrent.futures import ProcessPoolExecutor


def get_graph(attack_paths):
    """Getting the nodes and edges for an array of attack paths."""
    
    # Initializing the nodes and edges arrays.
    nodes = []
    edges = {}
    
    # Generating unique nodes.
    for attack_path in attack_paths:
        for node in attack_path:
            if node not in nodes:
                nodes.append(node)
    
    # Generating unique edges.
    for attack_path in attack_paths:
        
        # Checking if an edge is present.
        if len(attack_path) >= 2:
            for i in range(1, len(attack_path)):
                key = attack_path[i] + "|" + attack_path[i - 1]
                edges[key] = [attack_path[i], attack_path[i - 1]]
    
    return nodes, edges


def add_edge(nodes, edges, node_start, node_start_privilege, node_end, node_end_privilege, edge_desc, passed_edges):
    """
    Adding an edge to the attack graph and checking if nodes already exist.
    """
    raise NotImplementedError
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


def breadth_first_search(services: dict[str, dict[str, ]], networks: dict[str, dict[str, set]], gateways: set[str],
                         exploitable_vulnerabilities: dict[str, dict[str, dict[str, int]]]) \
        -> nx.DiGraph:
    """Breadth first search approach for generation of nodes and edges
    without generating attack paths."""
    
    # TODO
    raise NotImplementedError
    
    edges = {}
    nodes = {}
    passed_nodes = {}
    passed_edges = {}
    
    sub_graph = nx.DiGraph()
    
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
    
    return sub_graph


def generate_attack_graph(networks: dict[str, dict[str, set]], services: dict[str, dict[str,]],
                          exploitable_vulnerabilities: dict[str, dict[str, dict[str, int]]],
                          executor: ProcessPoolExecutor) -> (dict[str, nx.DiGraph], int):
    # TODO
    """Main pipeline for the attack graph generation algorithm."""
    
    # This is where the nodes and edges are going to be stored.
    attack_graph: dict[str, nx.DiGraph] = dict()
    
    da = time.time()
    
    # Breadth first search algorithm for generation of attack paths.
    print("Breadth-first search started.")
    
    for network in networks:
        gateways = networks[network]['gateways']
        sub_graph = breadth_first_search(services, networks, gateways, exploitable_vulnerabilities)
        attack_graph[network] = sub_graph

    print('Breadth-first-search took', time.time() - da, 'seconds.')
    
    return attack_graph, da


def update_by_networks(networks: dict[str, dict[str, set]], services: dict[str, dict[str, ]],
                       attack_graph: dict[str, nx.DiGraph],
                       exploitable_vulnerabilities: dict[str, dict[str, dict[str, int]]], executor: ProcessPoolExecutor,
                       affected_networks: list[str]):
    
    for network in affected_networks:
        gateways = networks[network]['gateways']
        sub_graph, bdf = breadth_first_search(services, networks, gateways, exploitable_vulnerabilities)
        attack_graph[network] = sub_graph


def get_graph_compose(attack_graph: dict[str, nx.DiGraph]):
    """This functions prints graph properties."""
    
    time_start = time.time()
    
    composed_graph = nx.compose_all([*attack_graph.values()])
    
    dcg = time.time() - time_start
    print('Finished connecting graph in', dcg, 'seconds.')
    return composed_graph, dcg
