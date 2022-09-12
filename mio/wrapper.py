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
This module wraps dirty works of IO like initialisation readings and file writings.
"""

from layers.merged_graph_layer import MergedGraphLayer

from mio import reader, writer
import time
import os


def init(argv: list) -> (dict[str], list[str]):
    """
    Initialise experimental environments
    Parameters:
        argv: sys.argv, where argv must be a list of 2
    Returns:
        config: config.yml file in form of dictionary
        examples: a list of example folders
    """
    # Opening the configuration file.
    config = reader.validate_config_file()
    
    # Checks if the command-line input and config file content is valid.
    examples = reader.validate_command_line_input(argv, config)
    
    return config, examples


def create_folders(example_basename: str, config: dict[str]) -> (str, str):
    """
    Create folder where the result files will be stored.
    Parameters:
        example_basename: where example folder is.
        config: configurations
    Returns:
        example_folder: absolute path
        result_folder: absolute path
    """
    example_folder = os.path.join(os.getcwd(), config['examples-path'], example_basename)
    result_folder = writer.create_result_folder(example_basename, config['examples-results-path'])
    
    return example_folder, result_folder


def visualise(merged_graph_layer: MergedGraphLayer, result_folder: str, times: int):
    """
    Visualise layers and save to file.
    Parameters:
        merged_graph_layer: MergedGraphLayer
        result_folder: where results are stored.
        times: the sub folder in result_folder, where i indicates times of writing
    """
    time_start = time.time()
    
    composed_graph_layer = merged_graph_layer.composed_graph_layer
    attack_graph_layer = composed_graph_layer.attack_graph_layer
    vulnerability_layer = attack_graph_layer.vulnerability_layer
    topology_layer = vulnerability_layer.topology_layer
    
    writer.write_topology_graph(topology_layer, result_folder, times)
    writer.write_gateway_graph(topology_layer, result_folder, times)
    writer.write_attack_graphs(attack_graph_layer, result_folder, times)
    writer.write_composed_graph(composed_graph_layer, result_folder, times)
    writer.write_merged_graph(merged_graph_layer, result_folder, times)
    
    print(f'Time for visualising: {time.time() - time_start} seconds.')


def print_summary(merged_graph_layer: MergedGraphLayer):
    """
    print graph properties.
    Parameters:
        merged_graph_layer: MergedGraphLayer
    """
    
    composed_graph_layer = merged_graph_layer.composed_graph_layer
    attack_graph_layer = composed_graph_layer.attack_graph_layer
    vulnerability_layer = attack_graph_layer.vulnerability_layer
    topology_layer = vulnerability_layer.topology_layer
    
    print(f'The number of nodes in the topology graph is {topology_layer.topology_graph.number_of_nodes()}')
    print(f'The number of edges in the topology graph is {topology_layer.topology_graph.number_of_edges()}')
    print(f'The number of nodes in the composed graph is {composed_graph_layer.composed_graph.number_of_nodes()}')
    print(f'The number of edges in the composed graph is {composed_graph_layer.composed_graph.number_of_edges()}')
    print(f'The number of nodes in the merged graph is {merged_graph_layer.merged_graph.number_of_nodes()}')
    print(f'The number of edges in the merged graph is {merged_graph_layer.merged_graph.number_of_edges()}\n\n')
