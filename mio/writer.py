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
This module is responsible for writing graphs and creating files.
"""

import os
import networkx as nx
from matplotlib import pyplot as plt
from layers.topology_layer import TopologyLayer
from layers.attack_graph_layer import AttackGraphLayer
from layers.merged_graph_layer import MergedGraphLayer
from layers.composed_graph_layer import ComposedGraphLayer


# noinspection DuplicatedCode
def write_composed_graph(composed_graph_layer: ComposedGraphLayer, result_dir: str, i: int):
    """
    Write attack graph to result directories in form of PNG file.
    Parameters:
        composed_graph_layer:
        result_dir: result directory to write
        i: the subdirectory in result_dir, where i indicates times of writing
    """
    composed_graph = composed_graph_layer.composed_graph
    composed_labels = composed_graph_layer.composed_labels
    composed_graph_dir = os.path.join(result_dir, str(i))
    
    if not os.path.exists(composed_graph_dir):
        os.makedirs(composed_graph_dir)

    composed_graph_path = os.path.join(composed_graph_dir, 'composed-graph.png')
    
    if not os.path.exists(composed_graph_path):
        
        plt.axis("off")
        pos = nx.spring_layout(composed_graph)
        nx.draw_networkx_nodes(composed_graph, pos)
        nx.draw_networkx_edges(composed_graph, pos)
        nx.draw_networkx_labels(composed_graph, pos)
        nx.draw_networkx_edge_labels(composed_graph, pos, edge_labels=composed_labels)
        plt.show()
        plt.savefig(composed_graph_dir, transparent=True)
    
    print(f'Composed graph is at: {composed_graph_path}.')


# noinspection DuplicatedCode
def write_topology_graph(topology_layer: TopologyLayer, result_dir: str, i: int):
    """
    Write topology graph to result directories in form of PNG file.
    Parameters:
        topology_layer: TopologyLayer object to write
        result_dir: result directory to write
        i: the subdirectory in result_dir, where i indicates times of writing
    """
    
    topology_graph = topology_layer.topology_graph
    
    topology_graph_dir = os.path.join(result_dir, str(i))
    
    if not os.path.exists(topology_graph_dir):
        os.makedirs(topology_graph_dir)
    
    topology_graph_path = os.path.join(topology_graph_dir, 'topology-graph.png')
    
    if not os.path.exists(topology_graph_path):
        
        plt.axis("off")
        pos = nx.spring_layout(topology_graph)
        nx.draw_networkx_nodes(topology_graph, pos)
        nx.draw_networkx_edges(topology_graph, pos)
        nx.draw_networkx_labels(topology_graph, pos)
        plt.show()
        plt.savefig(topology_graph_path, transparent=True)
    
    print(f'Topology graph is at: {topology_graph_path}.')


# noinspection DuplicatedCode
def write_gateway_graph(topology_layer: TopologyLayer, result_dir: str, i: int):
    """
    Write gateway graph to result directories in form of PNG file.
    Parameters:
        topology_layer: TopologyLayer object to write
        result_dir: result directory to write
        i: the subdirectory in result_dir, where i indicates times of writing
    """
    gateway_graph = topology_layer.gateway_graph
    gateway_graph_labels = topology_layer.gateway_graph_labels
    
    gateway_graph_dir = os.path.join(result_dir, str(i))
    if not os.path.exists(gateway_graph_dir):
        os.makedirs(gateway_graph_dir)
        
    gateway_graph_path = os.path.join(gateway_graph_dir, 'gateway-graph.png')
    
    if not os.path.exists(gateway_graph_path):
        
        plt.axis("off")
        pos = nx.spring_layout(gateway_graph)
        nx.draw_networkx_nodes(gateway_graph, pos)
        nx.draw_networkx_edges(gateway_graph, pos)
        nx.draw_networkx_labels(gateway_graph, pos)
        nx.draw_networkx_edge_labels(gateway_graph, pos, edge_labels=gateway_graph_labels)
        plt.show()
        plt.savefig(gateway_graph_path, transparent=True)
        
    print(f'Gateway graph is at: {gateway_graph_path}.')


# noinspection DuplicatedCode
def write_attack_graphs(attack_graph_layer: AttackGraphLayer, result_dir: str, i: int):
    
    attack_graph_dir = os.path.join(result_dir, str(i))
    
    if not os.path.exists(attack_graph_dir):
        os.makedirs(attack_graph_dir)
    
    for network in attack_graph_layer.attack_graph:
        attack_graph_path = os.path.join(attack_graph_dir, 'attack-graph-' + network + '.png')
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
            print(f'Sub graph is at: {attack_graph_path}.')


# noinspection DuplicatedCode
def write_merged_graph(merged_graph_layer: MergedGraphLayer, result_dir: str, i: int):
    """
    Write attack graph to result directories in form of PNG file.
    Parameters:
        merged_graph_layer:
        result_dir: result directory to write
        i: the subdirectory in result_dir, where i indicates times of writing
    """
    merged_graph = merged_graph_layer.merged_graph
    merged_graph_dir = os.path.join(result_dir, str(i))
    
    if not os.path.exists(merged_graph_dir):
        os.makedirs(merged_graph_dir)
    
    merged_graph_path = os.path.join(merged_graph_dir, 'merged-graph.png')
    
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
        plt.savefig(merged_graph_dir, transparent=True)
    
    print(f'Merged graph is at: {merged_graph_path}.')


def create_result_dir(experiment_dir: str, experiment_result_path: str) -> str:
    """
    Create result directory for an experiment directory.
    Parameters:
        experiment_dir: the experiment directory
        experiment_result_path: where the result directory will be created
    Returns:
        file path of the result directory
    """
    
    result_dir = os.path.join(os.getcwd(), experiment_result_path, experiment_dir)
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
    
    return result_dir
