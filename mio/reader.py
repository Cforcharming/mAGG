"""Module responsible for all the input reading and validation."""

from main import __version__
import errno
import json
import yaml
import sys
import os


def validate_command_line_input(arguments: list) -> int:
    if arguments.__contains__('-h') or arguments.__contains__('--help'):
        print("Option --help turned on" +
              "Command: ./main.py <example-folder-path> <goal-container>" +
              "<example-folder-path> is the folder that we want to analyze." +
              "<goal-container> is the name of the docker that the attacker wants to control.")
        return 0
    
    if arguments.__contains__('-v') or arguments.__contains__('--version'):
        print("mAGG version: " + __version__)
        return 0
    
    # Check if the user has entered right number of arguments.
    if len(arguments) > 2:
        print("Incorrect number of arguments.")
        return errno.EINVAL
    
    # Check if the specified folder exists.
    if not os.path.exists(arguments[1]):
        print("The entered example folder name does not exist: " + arguments[1])
        return errno.ENOTDIR
    
    # Check if there is a docker-compose.yml file in the specified folder.
    if "docker-compose.yml" not in os.listdir(arguments[1]):
        print("docker-compose.yml is missing in the folder: " + arguments[1])
        return errno.ENOENT
    
    return 0


def validate_config_file() -> (int, dict):
    """
    This function validates the config file content.
    """
    
    config_file = read_config_file()
    
    # Check if the main keywords are present in the config file.
    main_keywords = ["attack-vector-folder-path", "examples-results-path", "labels_edges", "generate_graphs",
                     "show_one_vul_per_edge"]
    
    for main_keyword in main_keywords:
        if main_keyword not in config_file.keys():
            print("'" + main_keyword + "' keyword is missing in the config file.", file=sys.stderr)
            return errno.EBADF
    
    # Check if the generate_graphs keyword has the right values
    generate_graphs = config_file["generate_graphs"]
    if type(generate_graphs) is not bool:
        print("Value: " + generate_graphs + " is invalid for keyword generate_graphs", file=sys.stderr)
        return errno.EBADF
    
    # Check if the show_one_vul_per_edge keyword has the right values
    show_one_vul_per_edge = config_file["show_one_vul_per_edge"]
    if type(show_one_vul_per_edge) is not bool:
        print("Value: " + show_one_vul_per_edge + " is invalid for keyword show_one_vul_per_edge", file=sys.stderr)
        return errno.EBADF
    
    # Check if the labels_edges keyword has the right values
    labels_edges = config_file["labels_edges"]
    if labels_edges != "single" and labels_edges != "multiple":
        print("Value: " + labels_edges + " is invalid for keyword labels_edges", file=sys.stderr)
        return errno.EBADF
    
    return 0, config_file


def read_attack_vector_files(attack_vector_folder_path: str) -> list[dict[str, ]]:
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


def read_topology(example_folder: str) -> dict[str, set[str]]:
    """Reads the topology .json file."""
    
    topology_path = os.path.join(example_folder, "topology.json")
    
    with open(topology_path) as topology_file:
        topology = json.load(topology_file)
    
    for service in topology:
        topology[service] = set(topology[service])
    
    return topology


def read_docker_compose_file(example_folder_path: str) -> dict[str, ]:
    """This function is responsible for reading the docker-compose file of the container."""
    
    with open(os.path.join(example_folder_path, "docker-compose.yml"), "r") as compose_file:
        docker_compose_file = yaml.full_load(compose_file)
    
    return docker_compose_file


def read_config_file() -> dict:
    """This function is responsible for reading the config file."""
    
    with open(os.path.join(os.getcwd(), "data/config.yml"), "r") as stream:
        try:
            config_file = yaml.full_load(stream)
        except yaml.YAMLError as exc:
            print(exc, file=sys.stderr)
            exit(errno.ENOENT)
    
    return config_file


def cache_parsed_images(example_folder: str) -> set[str]:
    
    files = os.listdir(example_folder)
    
    parsed_images = set()
    
    for file in files:
        if 'vulnerabilities' in file:
            image = file.replace('-vulnerabilities.json', '')
            parsed_images.add(image)
    
    return parsed_images
