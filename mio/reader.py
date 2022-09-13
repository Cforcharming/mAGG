#  Copyright 2022 Hanwen Zhang
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  Unless required by applicable law or agreed to in writing, software.
#  You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#  Distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""
Module responsible for all the input reading and validation.
"""

import main
import yaml
import sys
import os


def validate_command_line_input(argv: list, config: dict) -> list[str]:
    """
    Parameters:
        argv: sys.argv
        config: a dict of configs
    Returns:
        a list of example folders
    Raises:
        ValueError: if any args are invalid
    """
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
                  'full:                     run all examples in sub directory \'full-conn\''
                  '',
                  'real                      run all examples in sub directory \'designed\''
                  '',
                  '-v | --version | version: show version and license',
                  '',
                  '-h | --help | help:       print this message', sep='\n')
            sys.exit(0)
            
        case '-v' | '--version' | 'version':
            print(f'mAGG version: {main.__version__}', end='\n\n')
            print('''Copyright 2022 Hanwen Zhang
Licensed under the Apache License, Version 2.0 (the "License");
Unless required by applicable law or agreed to in writing, software.
 
Distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.''')
            sys.exit(0)
            
        case _:
            example_folders = []
            example_base = config['examples-path']
            
            for arg in argv[1:]:
                example_folder = os.path.join(example_base, arg)
                
                # Check if the specified folder exists.
                if not os.path.exists(example_folder):
                    raise ValueError(f'The entered example folder name does not exist: {arg}.')
                
                # Check if there is a docker-compose.yml file in the specified folder.
                if 'docker-compose.yml' not in os.listdir(example_folder):
                    raise ValueError(f'docker-compose.yml is missing in the folder: {arg}.')
                
                example_folders.append(arg)
            
    return example_folders


def validate_config_file() -> dict[str]:
    """
    This function validates the config file content.
    Returns:
        a dict of configs
    Raises:
        ValueError: if contents in config is invalid.
    """
    
    config_file = read_config_file()
    
    # Check if the main keywords are present in the config file.
    main_keywords = {'attack-vector-folder-path', 'examples-results-path', 'examples-path', 'nums-of-processes',
                     'generate-graphs', 'single-edge-label', 'single-exploit-per-node'}
    
    for main_keyword in main_keywords:
        if main_keyword not in config_file.keys():
            raise ValueError(f'Keyword \'{main_keyword}\' is missing in the config file.')
    
    # Check if the generate_graphs keyword has the right values
    generate_graphs = config_file['generate-graphs']
    if type(generate_graphs) is not bool:
        raise ValueError(f'Value \'{generate_graphs}\' is invalid for keyword \'generate-graphs\', it must be bool')
    
    # Check if the show_one_vul_per_edge keyword has the right values
    single_edge_label = config_file['single-edge-label']
    if type(single_edge_label) is not bool:
        raise ValueError(f'Value \'{single_edge_label}\' is invalid for keyword \'single-edge-label\', it must be bool')
    
    # Check if the labels_edges keyword has the right values
    single_exploit_per_node = config_file['single-exploit-per-node']
    if type(single_exploit_per_node) is not bool:
        raise ValueError(f'Value \'{single_exploit_per_node}\' is invalid for keyword \'single-exploit-per-node\', '
                         f'it must be bool')

    concurrency = config_file['nums-of-processes']
    if type(concurrency) is not int or concurrency < 0:
        raise ValueError(f'Value \'{concurrency}\' is invalid for keyword \'nums-of-processes\', '
                         f'it must be an integer no less than 0.')
    
    return config_file


def read_config_file() -> dict[str]:
    """
    Read config.yml file
    Returns:
        a dict of configs
    Raises:
        ValueError: if no such file
    """
    
    config_file_path = os.path.join(os.getcwd(), 'data/config.yml')
    
    if not os.path.exists(config_file_path):
        raise ValueError(f'No such file: {config_file_path}')
    
    with open(config_file_path, 'r') as stream:
        config_file = yaml.full_load(stream)
    
    return config_file
