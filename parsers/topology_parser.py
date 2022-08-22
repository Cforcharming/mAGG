#!/usr/bin/env python
"""Module responsible for manipulation of the topology of the docker system."""

import os
from graphviz import Graph
from mio import reader


def get_services(example_folder):
    """It returns a dictionary of all services defined in docker-compose.yml"""

    docker_compose_file = reader.read_docker_compose_file(example_folder)

    if "services" in docker_compose_file:
        return docker_compose_file["services"]
    else:
        return {}


def get_mapping_service_to_image_names(services, example_folder_path):
    """This function maps the service name to the real image name.

    In docker images get assigned different names based on how the
    docker-compose.yml file is constructed.
    This function helps us with that issue."""
    
    mapping = {}
    for service in services:
        content_service = services[service]
        
        # Checks if the 'image' keyword is present and names the service after it.
        if 'image' in content_service.keys():
            mapping[service] = content_service['image']
        
        # If not, it appends the folder name as a prefix to the service name.
        else:
            # Specific to docker: '-' and '_' are removed.
            parent_name = os.path.basename(example_folder_path).replace("-", "").replace("_", "")
            mapping[service] = os.path.basename(parent_name) + "_" + service
    
    return mapping


def create_topology_graph(topology):
    """This function creates a topology graph."""
    
    print("Executing the graph render...")
    edges = {}
    
    dot = Graph(comment="Topology Graph", format='png', engine='sfdp')
    for service in topology.keys():
        dot.node(service)
        for neighbour in topology[service]:
            if neighbour + "|" + service not in edges.keys():
                edges[service + "|" + neighbour] = [service, neighbour]
                dot.edge(service, neighbour)
    
    return dot


def parse_topology(example_folder):
    """ Function for parsing the topology of the docker system.

    Assumptions:
    1) We assume that the docker-compose file contains networks
    and the dockers are connected through these networks
    2) We assume that port mapping is done exclusively through docker-compose.yml"""
    
    print("Executing the topology parser...")

    services = get_services(example_folder)
    
    # Checks if the services are connected to the outside.
    topology = {"outside": []}
    networks = {'exposed': []}
    
    # Iteration through the first service.
    for first_service in services:
        
        # Check if network keyword exists in the first service.
        if "networks" in services[first_service].keys():
            first_service_networks = services[first_service]["networks"]
        else:
            
            # If it does not, it means that it is exposed to every other service.
            first_service_networks = ["exposed"]
        
        topology[first_service] = []
        for fn in first_service_networks:
            if networks.get(fn) is not None:
                networks[fn].append(first_service)
            else:
                networks[fn] = [first_service]

        # Iteration through the second service.
        for second_service in services:
            if first_service != second_service:
                
                # Check if network keyword exists in the second service.
                if "networks" in services[second_service].keys():
                    second_service_networks = services[second_service]["networks"]
                else:
                    
                    # If it does not, it means that it is exposed to every other service.
                    second_service_networks = "exposed"
                
                # Checks if the first and second service belong to the same network.
                for first_service_network in first_service_networks:
                    if first_service_network in second_service_networks:
                        # If they do, then they are added.
                        topology[first_service].append(second_service)
        
        # Check if the ports are mapped to the host machine
        # i.e. the docker is exposed to outside
        if "ports" in services[first_service].keys():
            topology["outside"].append(first_service)
            topology[first_service].append("outside")
            networks['exposed'].append(first_service)
    
    return topology, networks, services


def add(networks, topology, topology_graph: Graph, services, new_service, name):
    
    network = new_service['networks']
    to_add = []
    
    for n in network:
        if networks.get(n) is None:
            networks[n] = {name}
        else:
            for neighbour in networks[n]:
                if neighbour not in to_add:
                    topology[neighbour].append(name)
                    to_add.append(neighbour)
            networks[n].append(name)
    
    topology[name] = to_add
    topology_graph.node(name)
    
    for neighbour in to_add:
        topology_graph.edge(neighbour, name)
    
    services[name] = new_service
    

def delete(networks, topology, services, del_service, name):
    
    network = del_service['networks']
    
    for n in network:
        for neighbour in networks[n]:
            if neighbour != name and name in topology[neighbour]:
                topology[neighbour].remove(name)
    
    del topology[name]
    del services[name]
