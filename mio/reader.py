"""Module responsible for all the input reading and validation."""

from main import __version__
import errno
import yaml
import sys
import os


def validate_command_line_input(argv: list, config: dict) -> (int, list[str]):
    
    if len(argv) < 2:
        argv = [argv[0], '-h']
    
    match argv[1]:
        case 'full':
            example_folders = os.listdir(os.path.join(os.getcwd(), 'examples/full-conn'))
            example_folders = ['full-conn/' + e for e in example_folders]
            
        case 'real':
            example_folders = os.listdir(os.path.join(os.getcwd(), 'examples/designed'))
            example_folders = ['designed/' + e for e in example_folders]
            
        case '-h' | '--help' | 'help':
            print('Usage: mAGG [options] | [dir1 dir2 ..]',
                  'options:',
                  'dir1 dir2 dir3:           dirs must be in \'example-results\' of data/config.yml',
                  '                          dirs must contain a valid docker-compose file, and'
                  '                          may also containing vulnerability files',
                  '                          of images in format of clair json report.',
                  '',
                  '-v | --version | version: show version and license',
                  '-h | --help | help:       print this message', sep='\n')
            sys.exit(0)
            
        case '-v' | '--version' | 'version':
            print('mAGG version:', __version__, end='\n\n')
            print('''Copyright 2022 张瀚文

Licensed under the Apache License, Version 2.0 (the "License");
Unless required by applicable law or agreed to in writing, software.

Distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.''')
            sys.exit(0)
            
        case _:
            example_folders = []
            examples = os.listdir(config['examples-path'])
            for arg in argv[1:]:
                if arg not in example_folders and arg in examples:
                    # Check if the specified folder exists.
                    if not os.path.exists(arg):
                        print('The entered example folder name does not exist', arg)
                        return errno.ENOTDIR

                    # Check if there is a docker-compose.yml file in the specified folder.
                    if "docker-compose.yml" not in os.listdir(argv[1]):
                        print('docker-compose.yml is missing in the folder', arg)
                        return errno.ENOENT
                
                    example_folders.append(arg)
            
    return 0, example_folders


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
