"""Module responsible for manipulation of the topology of the docker system."""

from mio import reader
import networkx as nx
import time


def parse_compose(example_folder: str) -> (dict[str, dict[str, ]], dict[str, dict[str, set]]):
    """It returns a dictionary of all services defined in docker-compose.yml"""

    docker_compose: dict[str, ] = reader.read_docker_compose_file(example_folder)

    services: dict[str, dict[str, ]] = docker_compose.get("services", dict())
    networks: dict[str, ] = docker_compose.get('networks', dict())
    
    for network in networks:
        nodes = set(networks[network])
        networks[network] = {'nodes': nodes, 'gateways': set()}
    
    networks['exposed'] = {'nodes': {'outside'}, 'gateways': set()}
    return services, networks


def create_graphs(networks: dict[str, dict[str, set]], services: dict[str, dict[str, ]]) \
        -> (nx.Graph, nx.Graph, dict[(str, str), str]):
    """This function creates a topology graph."""

    topology_graph = nx.Graph()
    gateway_graph = nx.Graph()
    
    gateway_graph_labels = dict()
    
    for name in services:
        service: dict[str, ] = services[name]
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
                gateway_graph.add_edge('exposed', sn)
                gateway_graph_labels[('exposed', sn)] = name
    
    return topology_graph, gateway_graph, gateway_graph_labels


def parse_topology(example_folder: str) -> (dict[str, dict[str, set]], dict[str, dict[str, ]], set[str]):
    
    """ Function for parsing the topology of the docker system.

    Assumptions:
    1) We assume that the docker-compose file contains networks
    and the dockers are connected through these networks
    2) We assume that port mapping is done exclusively through docker-compose.yml"""
    
    time_start = time.time()
    print("Executing the topology parser...")

    services, networks = parse_compose(example_folder)
    services: dict[str, dict[str, ]]
    
    gateway_nodes = set()
    
    networks: dict[str, dict[str, set]]
    
    for name in services:
        service: dict[str, ] = services[name]
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
            networks['exposed']['nodes'].add(name)
            networks['exposed']['gateways'].add(name)
            gateway_nodes.add(name)
            
    duration_topology = time.time() - time_start
    print("Time elapsed: " + str(duration_topology) + " seconds.\n")
    
    return networks, services, gateway_nodes


def add(networks: dict[str, set[str]], topology: dict[str, set[str]], topology_graph: nx.Graph,
        services: dict[str, dict[str, ]], new_service: dict[str, ], name: str):
    # TODO
    
    network: set = new_service['networks']
    to_add = set()
    
    for n in network:
        network_to_update = networks.get(n, set())
        network_to_update.add(name)
        networks[n] = network_to_update
    
    topology[name] = to_add
    
    for neighbour in to_add:
        topology_graph.add_edge(neighbour, name)
    
    services[name] = new_service
    

def delete(networks: dict[str, set[str]], topology: dict[str, set[str]], services: dict[str, dict[str, ]], name: str):
    # TODO
    for n in services[name]['networks']:
        for neighbour in networks[n]:
            if neighbour != name and name in topology[neighbour]:
                topology[neighbour]: set
                topology[neighbour].remove(name)
    
    del topology[name]
    del services[name]
