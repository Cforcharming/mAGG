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
Layer for manipulation a composed attack graph.
Including class MergedGraphLayer
"""

from layers.composed_graph_layer import ComposedGraphLayer
import networkx as nx
import math
import time


class MergedGraphLayer:
    
    def __init__(self, composed_graph_layer: ComposedGraphLayer):
        
        print('Graph merging started.')
        tm = time.time()
        self._merged_graph = nx.DiGraph()
        self._merged_labels = dict()
        self._weighted_edges = list()
        self._composed_graph_layer = composed_graph_layer
        self.merge()
        tm = time.time() - tm
        print(f'Time for graph merging: {tm} seconds.')
        
    @property
    def merged_graph(self) -> nx.DiGraph:
        return self._merged_graph
    
    @property
    def composed_graph_layer(self) -> ComposedGraphLayer:
        return self._composed_graph_layer
    
    @merged_graph.setter
    def merged_graph(self, merged_graph: nx.DiGraph):
        self._merged_graph = merged_graph
    
    @composed_graph_layer.setter
    def composed_graph_layer(self, composed_graph_layer: ComposedGraphLayer):
        self._composed_graph_layer = composed_graph_layer
    
    # noinspection PyCallingNonCallable
    def merge(self):
        for label in self.composed_graph_layer.composed_labels:
            
            (start_node, privilege1), (end_node, privilege2) = label
            
            if start_node == end_node:
                continue
            
            vulnerabilities = self.composed_graph_layer.composed_labels[label]
            score = 0
            for vulnerability in vulnerabilities.split('\n'):
                if vulnerability != '':
                    scores = self.composed_graph_layer.attack_graph_layer.vulnerability_layer.scores
                    score = max(score, scores[vulnerability])
            weight_to_compare = MergedGraphLayer.__get_weight_from_score(score)
            new_label = (start_node, end_node)
            
            if new_label in self._merged_labels \
                    and weight_to_compare >= self._merged_labels[new_label]['weight']:
                continue
            
            self._merged_labels[new_label] = {'weight': weight_to_compare, 'CVE': vulnerabilities}
        
        for label in self._merged_labels:
            start_node, end_node = label
            self._weighted_edges.append((start_node, end_node, self._merged_labels[label]))
        
        self.merged_graph.add_edges_from(self._weighted_edges)
        
        for node in self.merged_graph.nodes:
            if self.merged_graph.out_degree(node) == 0:
                continue
            
            total_value = 0
            out_edges = self.merged_graph.out_edges(node)
            for out_edge in out_edges:
                weight = self._merged_labels[out_edge]['weight']
                total_value += weight
            for out_edge in out_edges:
                weight = self._merged_labels[out_edge]['weight']
                self._merged_labels[out_edge]['possibility'] = math.trunc(weight / total_value * 100) / 100
            
            nx.set_edge_attributes(self.merged_graph, self._merged_labels)
            
    def gen_defence_list(self, to_n: str, from_n='outside') -> dict[str, int]:
        
        if from_n not in self.merged_graph:
            raise ValueError(f'Start node {from_n} is not in the merged graph.')
        
        if to_n not in self.merged_graph:
            raise ValueError(f'Start node {to_n} is not in the merged graph.')
        
        tg = time.time()
        path_counts: dict[str, int] = dict()
        topology_layer = self.composed_graph_layer.attack_graph_layer.vulnerability_layer.topology_layer
        for gateway in topology_layer.gateway_nodes:
            degree: int = topology_layer.topology_graph.degree(gateway)
            path_counts[gateway] = degree
        
        for node in nx.shortest_path(self.merged_graph, from_n, to_n):
            if node in path_counts:
                path_counts[node] = path_counts[node] + 1
            else:
                path_counts[node] = 1
        tg = time.time() - tg
        print(f'The nodes to protect: {[*path_counts.keys()]}')
        print(f'Time for generating defence list: {tg} seconds.')
        return path_counts
    
    def deploy_honeypot(self, path_counts, minimum):
        
        attack_graph_layer = self.composed_graph_layer.attack_graph_layer
        vulnerability_layer = attack_graph_layer.vulnerability_layer
        topology_layer = vulnerability_layer.topology_layer
        
        affected_networks = set()
        
        image = 'nginx'
        
        td = time.time()
        h = 0
        for name in path_counts:
            
            if name == 'outside':
                continue
            
            if path_counts[name] < minimum:
                break
            
            old_networks = topology_layer.services[name]['networks']
            
            honeypot_name = 'honey-' + str(h)
            new_service = {'image': image, 'networks': old_networks}
            
            topology_layer[honeypot_name] = new_service
            vulnerability_layer[honeypot_name] = image
            
            for network in old_networks:
                affected_networks.add(network)
            
            print(f'Honeypot {honeypot_name} deployed at {name}.')
            h += 1
        
        td = time.time() - td
        print(f'Time for deploying honeypots: {td} seconds.')
        attack_graph_layer.update_by_networks(list(affected_networks))
        self.composed_graph_layer.get_graph_compose()
        self.merge()
    
    def get_bayesian_possibility(self, to_n: str, from_n='outside') -> float:
    
        if from_n not in self.merged_graph:
            raise ValueError(f'Start node {from_n} is not in the merged graph.')
    
        if to_n not in self.merged_graph:
            raise ValueError(f'Start node {to_n} is not in the merged graph.')
        
        possibility = 1.0
        shortest_path = nx.shortest_path(self.merged_graph, from_n, to_n, weight='weight')
        
        for i in range(0, len(shortest_path) - 1):
            start_node = shortest_path[i]
            end_node = shortest_path[i + 1]
            path_possibility = self._merged_labels[(start_node, end_node)]['possibility']
            possibility *= path_possibility
        
        return possibility

    def __setitem__(self, name: str, new_service: dict[str]):
        """
        set node to all layers
        Parameters:
            name: name of the node
            new_service: new service to set
        """
        
        image = new_service['image']
        new_networks = new_service['networks']
        
        attack_graph_layer = self.composed_graph_layer.attack_graph_layer
        vulnerability_layer = attack_graph_layer.vulnerability_layer
        topology_layer = vulnerability_layer.topology_layer
        
        topology_layer[name] = new_service
        vulnerability_layer[name] = image
        attack_graph_layer.update_by_networks(new_networks)
        self.composed_graph_layer.get_graph_compose()
        self.merge()
    
        print(f'Node added: {new_service}.')

    def __delitem__(self, name: str):
        """
        Remove a node from all layers
        Parameters:
            name: name of service to remove
        """
    
        attack_graph_layer = self.composed_graph_layer.attack_graph_layer
        vulnerability_layer = attack_graph_layer.vulnerability_layer
        topology_layer = vulnerability_layer.topology_layer
    
        affected_networks = topology_layer.services[name]['networks']
        
        del topology_layer[name]
        del vulnerability_layer[name]
        attack_graph_layer.update_by_networks(affected_networks)
        self.composed_graph_layer.get_graph_compose()
        self.merge()
    
        print(f'Node removed: {name}.')
    
    @staticmethod
    def __get_weight_from_score(score: float) -> float:
        weight = math.pow(1.2, -score)
        return weight
