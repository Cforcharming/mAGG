#!/usr/bin/env python
"""Module responsible for all the input reading and validation."""

from main import __version__
import errno
import json
import yaml
import sys
import os


def validate_command_line_input(arguments):
    
    if arguments.__contains__('-h') or arguments.__contains__('--help'):
        print("Option --help turned on" +
              "Command: ./main.py <example-folder-path> <goal-container>" +
              "<example-folder-path> is the folder that we want to analyze." +
              "<goal-container> is the name of the docker that the attacker wants to control.")
        exit(0)
    
    if len(arguments) == 1 or arguments.__contains__('-v') or arguments.__contains__('--version'):
        print("mAGG version: " + __version__)
        exit(0)
    
    # Check if the user has entered right number of arguments.
    if len(arguments) > 2:
        print("Incorrect number of arguments.", file=sys.stderr)
        exit(errno.EINVAL)
    
    # Check if the specified folder exists.
    if not os.path.exists(arguments[1]):
        print("The entered example folder name does not exist: " + arguments[1], file=sys.stderr)
        exit(errno.ENOTDIR)
    
    # Check if there is a docker-compose.yml file in the specified folder.
    content = os.listdir(arguments[1])
    if "docker-compose.yml" not in content:
        print("docker-compose.yml is missing in the folder: " + arguments[1], file=sys.stderr)
        exit(errno.ENOENT)


def validate_config_file():
    """
    This function validates the config file content.
    """
    
    config_file = read_config_file()
    
    # Check if the main keywords are present in the config file.
    main_keywords = ["attack-vector-folder-path",
                     "examples-results-path",
                     "mode",
                     "labels_edges",
                     "generate_graphs",
                     "show_one_vul_per_edge"]
    
    for main_keyword in main_keywords:
        if main_keyword not in config_file.keys():
            print("'" + main_keyword + "' keyword is missing in the config file.", file=sys.stderr)
            exit(errno.EBADF)
    
    # Check if the mode keyword has the right values
    mode = config_file["mode"]
    if mode != "offline" and mode != "online":
        print("Value: " + mode + " is invalid for keyword mode", file=sys.stderr)
        exit(errno.EBADF)
    
    # Check if the generate_graphs keyword has the right values
    generate_graphs = config_file["generate_graphs"]
    if type(generate_graphs) is not bool:
        print("Value: " + generate_graphs + " is invalid for keyword generate_graphs", file=sys.stderr)
        exit(errno.EBADF)
    
    # Check if the show_one_vul_per_edge keyword has the right values
    show_one_vul_per_edge = config_file["show_one_vul_per_edge"]
    if type(show_one_vul_per_edge) is not bool:
        print("Value: " + show_one_vul_per_edge + " is invalid for keyword show_one_vul_per_edge", file=sys.stderr)
        exit(errno.EBADF)
    
    # Check if the labels_edges keyword has the right values
    labels_edges = config_file["labels_edges"]
    if labels_edges != "single" and labels_edges != "multiple":
        print("Value: " + labels_edges + " is invalid for keyword labels_edges")
        exit(errno.EBADF)
    
    return config_file


def check_privileged_access(mapping_names, example_folder_path):
    """Checks if a container has the privileged flag."""
    docker_compose = read_docker_compose_file(example_folder_path)
    services = docker_compose["services"]
    privileged_access = {}
    for service in services:
        if "privileged" in services[service] and services[service]["privileged"]:
            privileged_access[mapping_names[service]] = True
        elif "volumes" in services[service]:
            volumes = services[service]["volumes"]
            # Check if docker socket is mounted
            socket_mounted = False
            for volume in volumes:
                if "/var/run/docker.sock:/var/run/docker.sock" in volume:
                    socket_mounted = True
            if socket_mounted:
                privileged_access[mapping_names[service]] = True
            else:
                privileged_access[mapping_names[service]] = False
        else:
            privileged_access[mapping_names[service]] = False
    
    return privileged_access


def read_attack_vector_files(attack_vector_folder_path):
    """It reads the attack vector files."""
    
    attack_vector_list = []
    
    attack_vector_filenames = os.listdir(attack_vector_folder_path)
    
    # Iterating through the attack vector files.
    for attack_vector_filename in attack_vector_filenames:
        
        # Load the attack vector.
        if not attack_vector_filename.startswith("nvdcve"):
            continue
        with open(os.path.join(attack_vector_folder_path, attack_vector_filename)) as att_vec:
            attack_vector_list.append(json.load(att_vec))
    
    return attack_vector_list


def read_topology(example_folder_path):
    """Reads the topology .json file."""
    
    config = read_config_file()
    folder_name = os.path.basename(example_folder_path)
    topology_path = os.path.join(config["examples-results-path"],
                                 folder_name,
                                 "topology.json")
    
    with open(topology_path) as topology_file:
        topology = json.load(topology_file)
    
    return topology


def read_vulnerabilities(vulnerabilities_folder_path, containers):
    """This function reads the .json file for the vulnerabilities of a container."""
    
    vulnerabilities = {}
    
    for container in containers:
        
        vulnerabilities_path = os.path.join(vulnerabilities_folder_path,
                                            container + "-vulnerabilities.json")
        if os.path.exists(vulnerabilities_path):
            with open(vulnerabilities_path) as vul_file:
                vulnerabilities_container = json.load(vul_file)
            vulnerabilities[container] = vulnerabilities_container
    
    return vulnerabilities


def read_docker_compose_file(example_folder_path):
    """This function is responsible for reading the docker-compose file of the container."""
    
    with open(os.path.join(example_folder_path, "docker-compose.yml"), "r") as compose_file:
        docker_compose_file = yaml.full_load(compose_file)
    
    return docker_compose_file


def read_config_file(old_root_path=""):
    """This function is responsible for reading the config file."""
    
    with open(os.path.join(old_root_path, "config.yml"), "r") as stream:
        try:
            config_file = yaml.full_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
    
    return config_file


def read_clairctl_config_file(clairctl_home):
    """This function is responsible for reading the clairctl config file."""
    
    with open(os.path.join(clairctl_home, "clairctl.yml"), "r") as clair_config:
        clair_config = yaml.full_load(clair_config)
    return clair_config
