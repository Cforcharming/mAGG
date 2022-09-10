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

from layers.composed_graph_layer import ComposedGraphLayer
from layers.vulnerability_layer import VulnerabilityLayer
from layers.attack_graph_layer import AttackGraphLayer
from layers.merged_graph_layer import MergedGraphLayer
from layers.topology_layer import TopologyLayer

from mio import reader, writer
import time
import os


def init(argv: list) -> (int, dict, list[str], int):
    times = 0
    
    # Opening the configuration file.
    stat, config = reader.validate_config_file()
    if stat != 0:
        return stat, None, None, None, None
    
    # Checks if the command-line input and config file content is valid.
    stat, examples = reader.validate_command_line_input(argv, config)
    if stat != 0:
        return stat, None, None, None, None
    
    return stat, config, examples, times


def create_folders(example_basename: str, config: dict) -> (str, str):
    """
    Create folder where the result files will be stored.
    """
    example_folder = os.path.join(os.getcwd(), config['examples-path'], example_basename)
    result_folder = writer.create_result_folder(example_basename, config["examples-results-path"])
    
    return example_folder, result_folder


def add_node(topology_layer: TopologyLayer, vulnerability_layer: VulnerabilityLayer,
             attack_graph_layer: AttackGraphLayer, composed_graph_layer: ComposedGraphLayer,
             merged_graph_layer: MergedGraphLayer, image: str, new_networks: list[str], name: str):
    
    new_service = {'image': image, 'networks': new_networks}
    
    vulnerability_layer.add_image(image)
    topology_layer.add_service(new_service, name)
    attack_graph_layer.update_by_networks(new_networks)
    composed_graph_layer.get_graph_compose()
    merged_graph_layer.merge()
    
    print("Node added:", new_service)


def del_node(topology_layer: TopologyLayer, attack_graph_layer: AttackGraphLayer,
             composed_graph_layer: ComposedGraphLayer, merged_graph_layer: MergedGraphLayer, name: str):
    
    affected_networks = topology_layer.services[name]['networks']
    del topology_layer[name]
    attack_graph_layer.update_by_networks(affected_networks)
    composed_graph_layer.get_graph_compose()
    merged_graph_layer.merge()
    
    print("Node deleted: ", name)


def visualise(topology_layer: TopologyLayer, attack_graph_layer: AttackGraphLayer,
              composed_graph_layer: ComposedGraphLayer, merged_graph_layer: MergedGraphLayer,
              result_folder: str, times: int):
    
    time_start = time.time()
    
    writer.write_topology_graph(topology_layer, result_folder, times)
    writer.write_gateway_graph(topology_layer, result_folder, times)
    writer.write_attack_graphs(attack_graph_layer, result_folder, times)
    writer.write_composed_graph(composed_graph_layer, result_folder, times)
    writer.write_merged_graph(merged_graph_layer, result_folder, times)
    
    print('Time for visualising:', time.time() - time_start, 'seconds.')


def print_summary(topology_nodes, topology_edges, attack_graph_nodes, attack_graph_edges):
    """Function responsible for printing the time and properties summary."""
    
    print('The number of nodes in the topology graph is', topology_nodes)
    print('The number of edges in the topology graph is', topology_edges)
    print('The number of nodes in the attack graph is', attack_graph_nodes)
    print('The number of edges in the attack graph is', attack_graph_edges, end='\n\n\n')
