"""Module responsible for manipulation of the topology of the docker system."""

from mio import reader
import networkx as nx
import time


def parse_compose(example_folder: str) -> (dict[str, dict[str, ]], dict[str, dict[str, set]]):
    """It returns a dictionary of all services defined in docker-compose.yml"""
    
    docker_compose: dict[str, ] = reader.read_docker_compose_file(example_folder)
    
    services: dict[str, dict[str, ]] = docker_compose.get("services", dict())
    networks: dict[str] = docker_compose.get('networks', dict())
    
    for network in networks:
        networks[network] = {'nodes': set(), 'gateways': set()}
    
    networks['exposed'] = {'nodes': {'outside'}, 'gateways': set()}
    return services, networks


def create_graphs(networks: dict[str, dict[str, set]], services: dict[str, dict[str, ]]) \
        -> (nx.Graph, nx.Graph, dict[(str, str), str]):
    """This function creates a topology graph."""
    
    start = time.time()
    print("Topology graph creation started.")
    
    topology_graph = nx.Graph()
    gateway_graph = nx.Graph()
    
    gateway_graph_labels = dict()
    
    for name in services:
        add_service_to_graph(networks, topology_graph, gateway_graph, gateway_graph_labels, services[name], name)
    
    dg = time.time() - start
    print('Time for creating topology graphs:', dg, 'seconds.')
    
    return topology_graph, gateway_graph, gateway_graph_labels, dg


def parse_topology(example_folder: str) -> (dict[str, dict[str, set]], dict[str, dict[str, ]], set[str], int):
    """ Function for parsing the topology of the docker system.

    Assumptions:
    1) We assume that the docker-compose file contains networks
    and the dockers are connected through these networks
    2) We assume that port mapping is done exclusively through docker-compose.yml"""
    
    time_start = time.time()
    print("Topology parsing started.")
    
    services, networks = parse_compose(example_folder)
    services: dict[str, dict[str]]
    
    gateway_nodes = set()
    
    networks: dict[str, dict[str, set]]
    
    for name in services:
        add_service_networks(networks, gateway_nodes, services[name], name)
    
    dt = time.time() - time_start
    print('Time for parsing topology:', dt, 'seconds.')
    
    return networks, services, gateway_nodes, dt


def add_service_networks(networks: dict[str, dict[str, set]], gateway_nodes: set[str], service: dict[str, ], name: str):
    service_network: list = service['networks']
    
    if len(service_network) >= 1:
        
        if len(service_network) > 1:
            gateway_nodes.add(name)
        
        for sn in service_network:
            
            if sn in networks:
                networks[sn]['nodes'].add(name)
                if len(service_network) > 1:
                    networks[sn]['gateways'].add(name)
            else:
                if len(service_network) > 1:
                    networks[sn] = {'nodes': {name}, 'gateways': {name}}
                else:
                    networks[sn] = {'nodes': {name}, 'gateways': set()}
            
            if "ports" in service.keys():
                networks[sn]['gateways'].add(name)
                gateway_nodes.add(name)
    
    if "ports" in service.keys():
        service['networks'].append('exposed')
        networks['exposed']['nodes'].add(name)
        networks['exposed']['gateways'].add(name)
        gateway_nodes.add(name)


def add_service_to_graph(networks: dict[str, dict[str, set]], topology_graph: nx.Graph, gateway_graph: nx.Graph,
                         gateway_graph_labels: dict[(str, str), str], service: dict[str, ], name: str):
    
    service_network = service['networks']
    for sn in service_network:
        neighbours = networks[sn]['nodes']
        for neighbour in neighbours:
            if neighbour != name:
                topology_graph.add_edge(name, neighbour)
        
        if len(service_network) > 1:
            for s2 in service_network:
                if sn != s2:
                    gateway_graph.add_edge(sn, s2)
                    gateway_graph_labels[(sn, s2)] = name
        
        if "ports" in service.keys():
            topology_graph.add_edge('outside', name)
            if sn != 'exposed':
                gateway_graph.add_edge('exposed', sn)
                gateway_graph_labels[('exposed', sn)] = name


def delete(networks: dict[str, dict[str, set]], services: dict[str, dict[str, ]],
           topology_graph: nx.Graph, gateway_graph: nx.Graph,
           gateway_nodes: set[str], gateway_graph_labels: dict[(str, str), str],
           name: str):
    
    service_to_delete = services[name]
    network_to_delete = service_to_delete['networks']
    
    for n in network_to_delete:
        network = networks[n]
        network['nodes'].remove(name)
        if name in network['gateways']:
            network['gateways'].remove(name)
    
    topology_graph.remove_node(name)
    if gateway_graph.has_node(name):
        gateway_graph.remove_node(name)
        gateway_nodes.remove(name)
        for (u, v) in gateway_graph_labels.copy():
            if u == name or v == name:
                del gateway_graph_labels[(u, v)]
    
    del services[name]
