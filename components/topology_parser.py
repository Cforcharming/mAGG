#!/usr/bin/env python
"""Module responsible for manipulation of the topology of the docker system."""

import os
from graphviz import Graph
from components import reader
from components import writer


def get_services(example_folder_path):
    """It returns a dictionary of all services defined in docker-compose.yml"""
    
    docker_compose_file = reader.read_docker_compose_file(example_folder_path)
    
    services = {}
    if "services" in docker_compose_file:
        services = docker_compose_file["services"]
    
    return services


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


def create_topology_graph(list_services, example_folder_path, example_results_path=""):
    """This function creates a topology graph."""
    
    print("Executing the graph render...")
    
    nodes = []
    edges = {}
    for service in list_services.keys():
        nodes.append(service)
        for neighbour in list_services[service]:
            if neighbour + "|" + service not in edges.keys():
                edges[service + "|" + neighbour] = [service, neighbour]
    
    dot = Graph(comment="Topology Graph", format='png', engine='sfdp')
    for node in nodes:
        dot.node(node)
    for edge in edges:
        dot.edge(edges[edge][0], edges[edge][1], contstraint='false')
    
    writer.write_topology_graph(dot, example_folder_path, example_results_path)


def parse_topology(example_folder_path, example_results_path=""):
    """ Function for parsing the topology of the docker system.

    Assumptions:
    1) We assume that the docker-compose file contains networks
    and the dockers are connected through these networks
    2) We assume that port mapping is done exclusively through docker-compose.yml"""
    
    print("Executing the topology parser...")
    
    # Checks if the services are specified.
    services = get_services(example_folder_path)
    
    # Checks if the services are connected to the outside.
    list_services = {"outside": []}
    
    # Iteration through the first service.
    for first_service_name in services:
        
        # Check if network keyword exists in the first service.
        if "networks" in services[first_service_name].keys():
            first_service_networks = services[first_service_name]["networks"]
        else:
            
            # If it does not, it means that it is exposed to every other service.
            first_service_networks = "exposed"
        list_services[first_service_name] = []
        
        # Iteration through the second service.
        for second_service_name in services:
            if first_service_name != second_service_name:
                
                # Check if network keyword exists in the second service.
                if "networks" in services[second_service_name].keys():
                    second_service_networks = services[second_service_name]["networks"]
                else:
                    
                    # If it does not, it means that it is exposed to every other service.
                    second_service_networks = "exposed"
                
                # Checks if the first and second service belong to the same network.
                for first_service_network in first_service_networks:
                    if first_service_network in second_service_networks:
                        # If they do, then they are added.
                        list_services[first_service_name].append(second_service_name)
        
        # Check if the ports are mapped to the host machine
        # i.e. the docker is exposed to outside
        if "ports" in services[first_service_name].keys():
            list_services["outside"].append(first_service_name)
            list_services[first_service_name].append("outside")
    
    # Writing the dictionary into a json file.
    writer.write_topology_file(list_services, example_folder_path, example_results_path)
    
    return list_services
