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


def read_command_line_input(argv: list, config: dict[str]) -> list[str]:
    """
    Parameters:
        argv: sys.argv
        config: a dict of configs
    Returns:
        a list of experiment directories
    Raises:
        ValueError: if any args are invalid
    """
    if len(argv) < 2:
        argv = [argv[0], '-h']
    
    match argv[1]:
        case 'full':
            experiment_dirs = os.listdir(os.path.join(os.getcwd(), 'examples/full-conn'))
            experiment_dirs = ['full-conn/' + e for e in experiment_dirs]
        
        case 'real':
            experiment_dirs = os.listdir(os.path.join(os.getcwd(), 'examples/designed'))
            experiment_dirs = ['designed/' + e for e in experiment_dirs]
        
        case '-h' | '--help' | 'help':
            print('Usage: mAGG [options] | [dir1 dir2 ..]',
                  'options:',
                  'dir1 dir2 dir3:           dirs must be in \'experiment-paths\' of data/config.yml',
                  '                          dirs must contain a valid docker-compose file, and'
                  '                          may also containing vulnerability files',
                  '                          of images in format of clair json report.',
                  '',
                  'full:                     run all examples in directory \'{experiment-paths}/full-conn\''
                  '',
                  'designed                  run all examples in sub directory \'{experiment-paths}/designed\''
                  '',
                  '-v | --version | version: show version and license',
                  '',
                  '-h | --help | help:       print this message', sep='\n')
            sys.exit(0)
        
        case '-v' | '--version' | 'version':
            print(f'mAGG version: {main.__version__}', end='\n\n')
            print('Copyright 2022 Hanwen Zhang',
                  'Licensed under the Apache License, Version 2.0 (the "License");',
                  'Unless required by applicable law or agreed to in writing, software.',
                  '',
                  'Distributed under the License is distributed on an "AS IS" BASIS,',
                  'WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.', sep='\n')
            sys.exit(0)
        
        case _:
            experiment_dirs = []
            experiment_base = config['experiment-paths']
            
            for arg in argv[1:]:
                experiment_dir = os.path.join(experiment_base, arg)
                
                # Check if the specified directory exists.
                if not os.path.exists(experiment_dir):
                    raise ValueError(f'No such directory: {arg}.')
                
                # Check if there is a docker-compose.yml file in the specified directory.
                if 'docker-compose.yml' not in os.listdir(experiment_dir):
                    raise ValueError(f'docker-compose.yml is missing in the directory: {arg}.')
                
                experiment_dirs.append(arg)
    
    return experiment_dirs


def validate_config_file() -> dict[str]:
    """
    This function validates the config file content.
    Returns:
        a dict of configs
    Raises:
        ValueError: if contents in config is invalid.
    """
    
    config = read_config_file()
    
    # Check if the main keywords are present in the config file.
    main_keywords = {'nvd-feed-path', 'experiment-paths', 'result-paths', 'topology-type', 'vulnerability-type',
                     'nums-of-processes', 'draw-graphs', 'single-edge-label', 'single-exploit-per-service',
                     'deploy-honeypots', 'target'}
    
    print('Checking data/config.yml...')
    
    for main_keyword in main_keywords:
        if main_keyword not in config.keys():
            raise ValueError(f'Keyword \'{main_keyword}\' is missing in the data/config.yml.')
    
    if not os.path.isdir(nvd_path := config['nvd-feed-path']):
        raise ValueError(f'Value\' {nvd_path}\' is invalid for keyword \'nvd-feed-path\', no such directory.')
    
    if not os.path.isdir(experiment_paths := config['experiment-paths']):
        raise ValueError(f'Value\' {experiment_paths}\' '
                         f'is invalid for keyword \'experiment-paths\', no such directory.')
    
    if not os.path.isdir(result_paths := config['result-paths']):
        raise ValueError(f'Value\' {result_paths}\' is invalid for keyword \'result-paths\', no such directory.')
    
    if type(concurrency := config['nums-of-processes']) is not int or concurrency < 0:
        raise ValueError(f'Value \'{concurrency}\' is invalid for keyword \'nums-of-processes\', '
                         f'it must be an integer no less than 0.')
    
    if type(draw_graphs := config['draw-graphs']) is not bool:
        raise ValueError(f'Value \'{draw_graphs}\' is invalid for keyword \'generate-graphs\', it must be bool.')
    
    if type(single_edge_label := config['single-edge-label']) is not bool:
        raise ValueError(f'Value \'{single_edge_label}\' is invalid for keyword \'single-edge-label\', '
                         f'it must be bool.')
    
    if type(single_exploit_per_service := config['single-exploit-per-service']) is not bool:
        raise ValueError(f'Value \'{single_exploit_per_service}\' is invalid for keyword \'single-exploit-per-service'
                         f'\', ' f'it must be bool.')
    
    if type(deploy_honeypots := config['deploy-honeypots']) is not bool:
        raise ValueError(f'Value \'{deploy_honeypots}\' is invalid for keyword \'deploy-honeypots\', it must be bool.')
    
    if config['target'] == 'None':
        config['target'] = None
    
    print('Done.')
    return config


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
