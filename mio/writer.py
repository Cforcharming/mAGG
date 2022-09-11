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

"""This module is responsible for writing operations."""

import os
import networkx as nx
from matplotlib import pyplot as plt
from layers.topology_layer import TopologyLayer
from layers.attack_graph_layer import AttackGraphLayer
from layers.merged_graph_layer import MergedGraphLayer
from layers.composed_graph_layer import ComposedGraphLayer


# noinspection DuplicatedCode
def write_composed_graph(composed_graph_layer: ComposedGraphLayer, result_folder: str, i: int):
    """
    Write attack graph to result folders in form of PNG file.
    
    Parameters:
        composed_graph_layer:
        result_folder: result folder to write
        i: the sub folder in result_folder, where i indicates times of writing
    """
    composed_graph = composed_graph_layer.composed_graph
    composed_labels = composed_graph_layer.composed_labels
    composed_graph_folder = os.path.join(result_folder, str(i))
    
    if not os.path.exists(composed_graph_folder):
        os.makedirs(composed_graph_folder)

    composed_graph_path = os.path.join(composed_graph_folder, 'composed-graph.png')
    
    if not os.path.exists(composed_graph_path):
        
        plt.axis("off")
        pos = nx.spring_layout(composed_graph)
        nx.draw_networkx_nodes(composed_graph, pos)
        nx.draw_networkx_edges(composed_graph, pos)
        nx.draw_networkx_labels(composed_graph, pos)
        nx.draw_networkx_edge_labels(composed_graph, pos, edge_labels=composed_labels)
        plt.show()
        plt.savefig(composed_graph_folder, transparent=True)
    
    print('Composed graph is at:', composed_graph_path)


# noinspection DuplicatedCode
def write_topology_graph(topology_layer: TopologyLayer, result_folder: str, i: int):
    """
    Write topology graph to result folders in form of PNG file.
    Parameters:
        topology_layer: TopologyLayer object to write
        result_folder: result folder to write
        i: the sub folder in result_folder, where i indicates times of writing
    """
    
    topology_graph = topology_layer.topology_graph
    
    topology_graph_folder = os.path.join(result_folder, str(i))
    
    if not os.path.exists(topology_graph_folder):
        os.makedirs(topology_graph_folder)
    
    topology_graph_path = os.path.join(topology_graph_folder, 'topology-graph.png')
    
    if not os.path.exists(topology_graph_path):
        
        plt.axis("off")
        pos = nx.spring_layout(topology_graph)
        nx.draw_networkx_nodes(topology_graph, pos)
        nx.draw_networkx_edges(topology_graph, pos)
        nx.draw_networkx_labels(topology_graph, pos)
        plt.show()
        plt.savefig(topology_graph_path, transparent=True)
    
    print('Topology graph is at:', topology_graph_path)


# noinspection DuplicatedCode
def write_gateway_graph(topology_layer: TopologyLayer, result_folder: str, i: int):
    """
    Write gateway graph to result folders in form of PNG file.
    Parameters:
        topology_layer: TopologyLayer object to write
        result_folder: result folder to write
        i: the sub folder in result_folder, where i indicates times of writing
    """
    gateway_graph = topology_layer.gateway_graph
    gateway_graph_labels = topology_layer.gateway_graph_labels
    
    gateway_graph_folder = os.path.join(result_folder, str(i))
    if not os.path.exists(gateway_graph_folder):
        os.makedirs(gateway_graph_folder)
        
    gateway_graph_path = os.path.join(gateway_graph_folder, 'gateway-graph.png')
    
    if not os.path.exists(gateway_graph_path):
        
        plt.axis("off")
        pos = nx.spring_layout(gateway_graph)
        nx.draw_networkx_nodes(gateway_graph, pos)
        nx.draw_networkx_edges(gateway_graph, pos)
        nx.draw_networkx_labels(gateway_graph, pos)
        nx.draw_networkx_edge_labels(gateway_graph, pos, edge_labels=gateway_graph_labels)
        plt.show()
        plt.savefig(gateway_graph_path, transparent=True)
        
    print('Gateway graph is at:', gateway_graph_path)


# noinspection DuplicatedCode
def write_attack_graphs(attack_graph_layer: AttackGraphLayer, result_folder: str, i: int):
    
    attack_graph_folder = os.path.join(result_folder, str(i))
    
    if not os.path.exists(attack_graph_folder):
        os.makedirs(attack_graph_folder)
    
    for network in attack_graph_layer.attack_graph:
        attack_graph_path = os.path.join(attack_graph_folder, 'attack-graph-' + network + '.png')
        if not os.path.exists(attack_graph_path):
            sub_graph = attack_graph_layer.attack_graph[network]
            sub_labels = attack_graph_layer.graph_labels[network]
            # noinspection DuplicatedCode
            plt.axis("off")
            pos = nx.spring_layout(sub_graph)
            nx.draw_networkx_nodes(sub_graph, pos)
            nx.draw_networkx_edges(sub_graph, pos)
            nx.draw_networkx_labels(sub_graph, pos)
            nx.draw_networkx_edge_labels(sub_graph, pos, edge_labels=sub_labels)
            plt.show()
            plt.savefig(attack_graph_path, transparent=True)
            print('Sub graph is at:', attack_graph_path)


# noinspection DuplicatedCode
def write_merged_graph(merged_graph_layer: MergedGraphLayer, result_folder: str, i: int):
    """
    Write attack graph to result folders in form of PNG file.

    Parameters:
        merged_graph_layer:
        result_folder: result folder to write
        i: the sub folder in result_folder, where i indicates times of writing
    """
    merged_graph = merged_graph_layer.merged_graph
    merged_graph_folder = os.path.join(result_folder, str(i))
    
    if not os.path.exists(merged_graph_folder):
        os.makedirs(merged_graph_folder)
    
    merged_graph_path = os.path.join(merged_graph_folder, 'merged-graph.png')
    
    if not os.path.exists(merged_graph_path):
        plt.axis("off")
        pos = nx.spring_layout(merged_graph)
        nx.draw_networkx_nodes(merged_graph, pos)
        nx.draw_networkx_edges(merged_graph, pos)
        nx.draw_networkx_labels(merged_graph, pos)
        nx.draw_networkx_edge_labels(merged_graph, pos)
        edge_labels = nx.get_edge_attributes(merged_graph, 'possibility')
        nx.draw_networkx_edge_labels(merged_graph, pos, edge_labels)
        plt.show()
        plt.savefig(merged_graph_folder, transparent=True)
    
    print('Merged graph is at:', merged_graph_path)


def create_result_folder(example_folder: str, examples_result_path: str) -> str:
    """
    Create result folder for an example folder.
    Parameters:
        example_folder: the example folder
        examples_result_path: where the result folder will be created
    Returns:
        file path of the result folder
    """
    
    result_folder = os.path.join(os.getcwd(), examples_result_path, example_folder)
    if not os.path.exists(result_folder):
        os.makedirs(result_folder)
    
    return result_folder
