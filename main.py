#!/usr/bin/env python
"""Main module responsible for the attack graph generation pipeline."""

# %%
import os
import sys
import time
import errno

from parsers import vulnerability_parser, attack_graph_parser, topology_parser
from mio import writer, reader

__version__ = "1.0-dev2"


# %%
def main(argv):
    """
    Main function responsible for running the attack graph generation pipeline.
    """
    
    # Checks if the command-line input and config file content is valid.
    
    times = 0
    reader.validate_command_line_input(argv)
    # Opening the configuration file.
    config = reader.validate_config_file()
    example_folder = os.path.join(os.getcwd(), argv[1])
    
    # Parsing the topology of the docker containers.
    time_start = time.time()
    topology, networks, services = topology_parser.parse_topology(example_folder)
    duration_topology = time.time() - time_start
    print("Time elapsed: " + str(duration_topology) + " seconds.\n")
    
    mapping_names = topology_parser.get_mapping_service_to_image_names(services, example_folder)
    
    # Visualizing the topology graph.
    time_start = time.time()
    topology_graph = topology_parser.create_topology_graph(topology)
    duration_visualization = time.time() - time_start
    print("Time elapsed: " + str(duration_visualization) + " seconds.\n")
    
    # Parsing the vulnerabilities for each docker container.
    time_start = time.time()
    parsed_images = reader.cache_parsed_images(example_folder)
    vulnerabilities = vulnerability_parser.parse_vulnerabilities(example_folder, parsed_images, services, mapping_names)
    duration_vulnerabilities = time.time() - time_start
    print("Time elapsed: " + str(duration_vulnerabilities) + " seconds.\n")
    
    if not vulnerabilities.keys():
        print("There is a mistake with the vulnerabilities. Terminating the function...")
        return errno.ENOENT

    # Read the attack vector files.
    attack_vector_files = reader.read_attack_vector_files(config["attack-vector-folder-path"])
    
    # Merging the attack vector files and creating an attack vector dictionary.
    attack_vector_dict = attack_graph_parser.get_attack_vector(attack_vector_files)

    #  Getting the attack graph nodes and edges from the attack paths.
    
    example_folders = os.listdir(os.path.join(os.getcwd(), 'examples/full-conn'))
    
    for example_folder in example_folders:
        print('\n\n\n**************************' + example_folder + '**************************\n\n\n')
        example_folder = os.path.join(os.getcwd(), 'examples/full-conn', example_folder)
        # Create folder where the result files will be stored.
        result_folder = writer.create_result_folder(os.path.join('full-conn', os.path.basename(example_folder)), config)
        
        topology, networks, services = topology_parser.parse_topology(example_folder)
        mapping_names = topology_parser.get_mapping_service_to_image_names(services, example_folder)
        exploitable_vulnerabilities, dvp = attack_graph_parser.get_exploitable_vulnerabilities(
            topology, vulnerabilities, mapping_names, attack_vector_dict, config["preconditions-rules"],
            config["postconditions-rules"])
        
        print("Start with attack graph generation...")
        nodes, edges, passed_nodes, passed_edges, duration_bdf = attack_graph_parser.\
            generate_attack_graph(topology, exploitable_vulnerabilities)
        print("Time elapsed: " + str(duration_bdf + dvp) + " seconds.\n")
        
        # duration_graph_properties, attack_graph = attack_graph_parser.\
        #     print_graph_properties(config["labels_edges"], nodes, edges)
        
        for element in edges.keys():
            edges[element] = [edges[element][0]]
        
        # Visualizing the attack graph.
        # times = visualise(topology, result_folder, times, config['labels_edges'], nodes, edges)
        
        # Printing time summary of the attack graph generation.
        writer.print_summary(config['generate_graphs'], duration_topology=duration_topology,
                             duration_vulnerabilities=duration_vulnerabilities,
                             duration_bdf=duration_bdf,
                             duration_vulnerabilities_preprocessing=dvp,
                             # duration_graph_properties=duration_graph_properties,
                             duration_visualization=duration_visualization)


def add_node(name, image, network, vulnerabilities, parsed_images, example_folder, networks, topology, topology_graph,
             services, mapping_names, attack_vector_dict, config, nodes, edges, passed_nodes, passed_edges):
    
    new_service = {'image': image, 'networks': network}
    
    vulnerability_parser.add(vulnerabilities, parsed_images, example_folder, image)
    
    topology_parser.add(networks, topology, topology_graph, services, new_service, name)
    
    mapping_names[name] = image
    exploitable_vulnerabilities, dvp = attack_graph_parser.get_exploitable_vulnerabilities(
        topology, vulnerabilities, mapping_names, attack_vector_dict, config["preconditions-rules"],
        config["postconditions-rules"])
    attack_graph_parser.add(nodes, edges, passed_nodes, passed_edges, topology, name, exploitable_vulnerabilities)
    
    print("Node added")


def del_node(name, networks, topology, services, mapping_names, nodes, edges, passed_nodes, passed_edges, attack_graph):
    del_service = services[name]
    
    topology_parser.delete(networks, topology, services, del_service, name)
    attack_graph_parser.delete(name, nodes, edges, passed_nodes, passed_edges, attack_graph)
    del mapping_names[name]
    
    print("Node deleted")


def visualise(topology, result_folder, times, labels_edges, nodes, edges):
    time_start = time.time()

    writer.write_topology(topology, result_folder, times)
    topology_graph = topology_parser.create_topology_graph(topology)
    writer.write_topology_graph(topology_graph, result_folder, times)
    writer.write_attack_graph(labels_edges, nodes, edges, result_folder, times)
    
    duration_visualization = time.time() - time_start
    print("Time elapsed: " + str(duration_visualization) + " seconds.\n")
    
    return times + 1


if __name__ == "__main__":
    exit(main(sys.argv))
