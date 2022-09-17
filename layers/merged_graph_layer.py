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
from collections import deque
import networkx as nx
import math
import time


class MergedGraphLayer:
    """
    Encapsulation of merged graph over a network for bayesian probabilities.
    Properties:
        merged_graph: a nx.DiGraph, merging the nodes of attack graphs
        
        merged_labels: labels for merged_graph

        composed_graph_layer: ComposedGraphLayer binding
        
        node_probabilities: a dict containing bayesian probabilities
    """
    
    def __init__(self, composed_graph_layer: ComposedGraphLayer):
        """
        Parameters:
             composed_graph_layer: ComposedGraphLayer to bind
        """
        print('Graph merging started.')
        tm = time.time()
        self._merged_graph = nx.DiGraph()
        self._merged_labels = dict()
        self._weighted_edges = list()
        self._edge_start_from = dict()
        self._composed_graph_layer = composed_graph_layer
        self._node_probabilities = None
        self.merge()
        tm = time.time() - tm
        print(f'Time for graph merging: {tm} seconds.')
    
    @property
    def merged_graph(self) -> nx.DiGraph:
        """
        Returns:
            merged_graph: a nx.DiGraph, merging the nodes of attack graphs
        """
        return self._merged_graph
    
    @property
    def merged_labels(self) -> dict[(str, str), dict[str]]:
        """
        Returns:
             merged_labels: labels for merged_graph
        """
        return self._merged_labels
    
    @property
    def composed_graph_layer(self) -> ComposedGraphLayer:
        """
        Returns:
            composed_graph_layer: ComposedGraphLayer binding
        """
        return self._composed_graph_layer
    
    @property
    def node_probabilities(self) -> dict[str, float]:
        """
        Returns:
            node_probabilities: a dict containing bayesian probabilities
        """
        return self._node_probabilities
    
    @merged_graph.setter
    def merged_graph(self, merged_graph: nx.DiGraph):
        self._merged_graph = merged_graph
    
    @composed_graph_layer.setter
    def composed_graph_layer(self, composed_graph_layer: ComposedGraphLayer):
        self._composed_graph_layer = composed_graph_layer
    
    @merged_labels.setter
    def merged_labels(self, merged_labels: dict[(str, str), dict[str]]):
        self._merged_labels = merged_labels
    
    @node_probabilities.setter
    def node_probabilities(self, node_probabilities: dict[str, float]):
        self._node_probabilities = node_probabilities
    
    # noinspection PyCallingNonCallable
    def merge(self):
        """
        Merging composed graphs, where same nodes with different privileges are treated as one.
        Then compute the weight by CVSS score.
        """
        
        tm = time.time()
        
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
            
            if new_label in self.merged_labels \
                    and weight_to_compare >= self.merged_labels[new_label]['weight']:
                continue
            
            self.merged_labels[new_label] = {'weight': weight_to_compare, 'CVE': vulnerabilities}
            
            self._edge_start_from: dict[str, set[(str, str)]]
            if start_node in self._edge_start_from:
                self._edge_start_from[start_node].add(new_label)
            else:
                self._edge_start_from[start_node] = {new_label}
        
        for node in self._edge_start_from:
            
            total_value = 0
            out_edges = self._edge_start_from[node]
            for out_edge in out_edges:
                weight = self.merged_labels[out_edge]['weight']
                total_value += 1 - weight
            for out_edge in out_edges:
                weight = self.merged_labels[out_edge]['weight']
                self.merged_labels[out_edge]['probability'] = math.trunc((1 - weight) / total_value * 100) / 100
        
        for label in self.merged_labels:
            start_node, end_node = label
            self._weighted_edges.append((start_node, end_node, self.merged_labels[label]))
        
        self.merged_graph.add_edges_from(self._weighted_edges)
        self.__get_bayesian_probabilities()
        
        tm = time.time() - tm
        print(f'Time for merging graphs: {tm} seconds.')
    
    def gen_defence_list(self, to_n: str = None, from_n='outside') -> dict[str, int]:
        """
        Generate a list of nodes to deploy honeypots, based on connectivities and probabilities
        Parameters
            to_n:
            from_n:
        Returns:
            A list of nodes to deploy honeypots.
        """
        if from_n not in self.merged_graph:
            raise ValueError(f'Start node {from_n} is not in the merged graph.')
        
        if to_n is not None and to_n not in self.merged_graph:
            raise ValueError(f'End node {to_n} is not in the merged graph.')
        
        tg = time.time()
        path_counts: dict[str, int] = dict()
        topology_layer = self.composed_graph_layer.attack_graph_layer.vulnerability_layer.topology_layer
        for gateway in topology_layer.gateway_nodes:
            degree: int = topology_layer.topology_graph.degree(gateway)
            path_counts[gateway] = degree

        if to_n is not None:
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
        """
        Deploy honeypots based on the list
        Parameters:
            path_counts: list to deploy
            minimum: path counts values, the lower, more honeypots will be deployed
        """
        
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
    
    def __get_bayesian_probabilities(self, from_n='outside'):
        """
        Get bayesian probabilities for all nodes presenting in networks
        Parameters:
            from_n: where search starts
        """
        
        self.node_probabilities = dict()
        
        if from_n not in self.merged_graph.nodes:
            raise ValueError(f'node \'{from_n}\' undefined in merged graph.')
        
        self.node_probabilities[from_n] = 1
        
        queue = deque()
        queue.append(from_n)
        
        while len(queue) > 0:
            self.breadth_first_bayesian(queue)
    
    def breadth_first_bayesian(self, queue: deque):
        """
        breadth first search throw nodes for bayesian probabilities
        Parameter
            queue: queue object
        """
        has_bayesian = queue.popleft()
        
        topology_layer = self.composed_graph_layer.attack_graph_layer.vulnerability_layer.topology_layer
        neighbours = topology_layer.get_neighbours(topology_layer.services, topology_layer.networks, has_bayesian)
        
        for neighbour in neighbours:
            
            if neighbour not in self.merged_graph.nodes:
                continue
            
            if neighbour in self.node_probabilities:
                continue
            
            edge = (has_bayesian, neighbour)
            
            neighbour_probability = 0
            
            if 'honey' not in neighbour:
                if edge in self.merged_labels:
                    neighbour_probability += self.node_probabilities[has_bayesian] \
                        * self.merged_labels[edge]['probability']
                
                for neighbour_of_neighbour in neighbours:
                    
                    if neighbour_of_neighbour not in self.merged_graph.nodes:
                        continue
                    
                    start_edge = (has_bayesian, neighbour_of_neighbour)
                    end_edge = (neighbour_of_neighbour, neighbour)
                    if start_edge not in self.merged_labels or end_edge not in self.merged_labels:
                        continue
                    
                    neighbour_probability += self.merged_labels[start_edge]['probability'] \
                        * self.merged_labels[end_edge]['probability']
            
            if neighbour in topology_layer.gateway_nodes:
                queue.append(neighbour)
            
            self.node_probabilities[neighbour] = neighbour_probability
    
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
    def compare_rates(nodes1: dict[str, float], nodes2: dict[str, float], to_n: str = None):
        """
        Compare bayesian probabilities
        Parameters:
            nodes1: set of nodes as self.node_probabilities
            nodes2: set of nodes as self.node_probabilities
            to_n: if not None, compare to_n only. Default: None
        """
        if to_n is not None:
            if to_n not in nodes1:
                raise ValueError(f'End node {to_n} is not in the merged graph.')
            p1 = nodes1[to_n]
            p2 = nodes2[to_n]
            if p1 != 0:
                rate = p1 - p2 / p1
            else:
                rate = 1
            print(
                f'Probability before and after deploying: {math.trunc(p1 * 100) / 100},  {math.trunc(p2 * 100) / 100},'
                f' {math.trunc(rate * 100) / 100} less')
            
            return
            
        all_down = 0
        for node in nodes1:
            p1 = nodes1[node]
            p2 = nodes2[node]
            if p1 != 0:
                rate = p1 - p2 / p1
            else:
                rate = 1
            all_down += rate
            print(
                f'Probability before and after deploying: {math.trunc(p1 * 100) / 100},  {math.trunc(p2 * 100) / 100},'
                f' {math.trunc(rate * 100) / 100} less')
        if len(nodes1) > 0:
            all_down = all_down / len(nodes1)
        print(f'Overall probability is lowered by {all_down}')
    
    @staticmethod
    def __get_weight_from_score(score: float) -> float:
        """
        weight of an edge with CVE vulnerability is defined as weight = 1.2^(-score)
        Parameters:
            score: CVSS score
        Returns:
            weight from score
        """
        
        weight = 1.2 ** -score
        return weight
