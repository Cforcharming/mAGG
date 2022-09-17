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
Layer for manipulation of the attack graphs of subnets.
Including class AttackGraphLayer
"""

import time
import networkx as nx
from collections import deque
from concurrent.futures import Executor, Future, wait

from layers.topology_layer import TopologyLayer
from layers.vulnerability_layer import VulnerabilityLayer


class AttackGraphLayer:
    """
    Encapsulation of attack graphs subnets.
    Properties:
        attack_graph: a dictionary of nx.DiGraph, where members are attack graphs for a subnet.
        
        graph_labels: labels for attack graphs, containing detailed CVE entries.
        
        vulnerability_layer: VulnerabilityLayer binding
    """
    
    def __init__(self, vulnerability_layer: VulnerabilityLayer, executor: Executor = None):
        """
        Initialise the attack graph layer
        Parameters:
            vulnerability_layer: VulnerabilityLayer binding
            executor: concurrent.futures.Executor or None
        """
        
        self._attack_graph = dict()
        self._graph_labels = dict()
        self._executor = executor
        self._vulnerability_layer = vulnerability_layer
        
        print('Attack graphs of subnets generation started.')
        start = time.time()

        self.update_by_subnets([*self._vulnerability_layer.topology_layer.subnets.keys()])

        da = time.time() - start
        print(f'Time for attack graphs of subnets generation: {da} seconds.')

    @property
    def attack_graph(self) -> dict[str, nx.DiGraph]:
        """
        Returns:
            a dictionary of nx.DiGraph, where members are attack graphs for a subnet.
        """
        return self._attack_graph
    
    @property
    def graph_labels(self) -> dict[str, dict[((str, str), (str, str)), str]]:
        """
        Returns:
            labels for attack graphs, containing detailed CVE entries.
        """
        return self._graph_labels
    
    @property
    def vulnerability_layer(self) -> VulnerabilityLayer:
        """
        Returns:
            VulnerabilityLayer binding
        """
        return self._vulnerability_layer
    
    @attack_graph.setter
    def attack_graph(self, attack_graph: dict[str, nx.DiGraph]):
        self._attack_graph = attack_graph
    
    @graph_labels.setter
    def graph_labels(self, graph_labels: dict[str, dict[((str, str), (str, str)), str]]):
        self._graph_labels = graph_labels
    
    def update_by_subnets(self, affected_subnets: list[str]):
        """
        Update attack graphs with a list of subnets
        Parameters:
            affected_subnets: list of subnets to update attack graph
        """
        
        futures: list[Future] = list()
        
        services = self.vulnerability_layer.topology_layer.services
        subnets = self.vulnerability_layer.topology_layer.subnets
        exploitable_vulnerabilities = self.vulnerability_layer.exploitable_vulnerabilities
        single_exploit = self.vulnerability_layer.config['single-exploit-per-service']
        single_label = self.vulnerability_layer.config['single-edge-label']
        
        if self._executor is not None:
            for subnet in affected_subnets:
                future = self._executor.submit(generate_sub_graph, services, subnets, subnet,
                                               exploitable_vulnerabilities, single_exploit, single_label)
                future.add_done_callback(update(self.attack_graph, self.graph_labels, subnet))
                futures.append(future)

        elif 'exposed' in affected_subnets:
            composed_graph, composed_labels = generate_full_from_exposed(services, exploitable_vulnerabilities,
                                                                         subnets, single_exploit, single_label)
            self.attack_graph['full'] = composed_graph
            self.graph_labels['full'] = composed_labels

        else:
            for subnet in affected_subnets:
                sub_graph, sub_labels = \
                    generate_sub_graph(services, subnets, subnet, exploitable_vulnerabilities,
                                       single_exploit, single_label)
                self.attack_graph[subnet] = sub_graph
                self.graph_labels[subnet] = sub_labels

        if self._executor is not None:
            wait(futures)
        
        for subnet in [*self.graph_labels.keys()]:
            if len(self.graph_labels[subnet]) == 0:
                del self.graph_labels[subnet]
                del self.attack_graph[subnet]


def update(attack_graph: dict[str, nx.DiGraph], graph_labels: dict[str, dict[((str, str), (str, str)), (str, str)]],
           subnet: str):
    """
    Update attack_graph and graph_labels according to future results
    Parameters:
        attack_graph:
        graph_labels:
        subnet:
    Returns:
        a function with future as only parameter.
    """
    def cbs(future: Future):
        """
        Concurrent callback functions for Future objects.
        Parameter:
            future: concurrent.futures.Future
        
        """
        sub_graph, sub_labels = future.result()
        attack_graph[subnet] = sub_graph
        graph_labels[subnet] = sub_labels
    return cbs


def generate_sub_graph(services: dict[str, dict[str]], subnets: dict[str, dict[str, set]], subnet: str,
                       exploitable_vulnerabilities: dict[str, dict[str, dict]],
                       single_exploit: bool, single_label: bool) \
        -> (nx.DiGraph, dict[((str, str), (str, str)), str]):
    """
    Generate attack graph for full connected subnets.
    Parameters:
        services:
        subnets:
        subnet:
        exploitable_vulnerabilities:
        single_exploit:
        single_label:
    Returns:
        a nx.Digraph object and its labels in dict
    """
    
    sub_graph = nx.DiGraph()
    sub_labels: dict[((str, str), (str, str)), str] = dict()
    
    gateways: set[str] = subnets[subnet]['gateways']
    neighbours: set[str] = subnets[subnet]['services']
    
    exploited_vulnerabilities: dict[(str, str), set[str]] = dict()
    
    if 'outside' in neighbours:
        gateways.add('outside')
    
    for gateway in gateways:
        
        if gateway == 'outside':
            gateway_post_privileges = {4: ['']}
        else:
            gateway_post_privileges: dict[int, list[str]] = exploitable_vulnerabilities[gateway]['post_values']
        
        depth_stack = deque()
        exploited_services: set[str] = {gateway}
        
        for current_privilege in gateway_post_privileges:
            depth_stack.append((gateway, current_privilege))
            
        while len(depth_stack) > 0:
            depth_first_search(exploited_services, exploited_vulnerabilities, services, subnets,
                               exploitable_vulnerabilities, sub_labels, depth_stack,
                               single_exploit, single_label, neighbours)
    
    sub_graph.add_edges_from([*sub_labels.keys()])
    print(f'Generated sub attack graph for subnet \'{subnet}\'', flush=True)
    return sub_graph, sub_labels


def generate_full_from_exposed(services: dict[str, dict[str]], exploitable_vulnerabilities: dict[str, dict[str, dict]],
                               subnets: dict[str, dict[str, set]], single_exploit: bool, single_label: bool) \
        -> (nx.DiGraph, dict[((str, str), (str, str)), str]):
    """
    Generate a full attack graph from exposed services.
    Parameters:
        services:
        exploitable_vulnerabilities:
        subnets:
        single_exploit:
        single_label:
    Returns:
        a nx.Digraph object and its labels in dict
    """
    
    composed_graph = nx.DiGraph()
    composed_labels: dict[((str, str), (str, str)), str] = dict()
    
    exploited_vulnerabilities: dict[(str, str), set[str]] = dict()
    depth_stack = deque()
    depth_stack.append(('outside', VulnerabilityLayer.get_privilege_value('ADMIN')))
    exploited_services: set[str] = {'outside'}

    while len(depth_stack) > 0:
        depth_first_search(exploited_services, exploited_vulnerabilities, services, subnets,
                           exploitable_vulnerabilities, composed_labels, depth_stack, single_exploit, single_label)
    
    composed_graph.add_edges_from([*composed_labels.keys()])
    print('Generated full attack graph from outside.', flush=True)
    return composed_graph, composed_labels


def depth_first_search(exploited_services: set[str], exploited_vulnerabilities: dict[(str, str), set[str]],
                       services: dict[str, dict[str]], subnets: dict[str, dict[str, set]],
                       exploitable_vulnerabilities: dict[str, dict[str, dict]],
                       sub_labels: dict[((str, str), (str, str)), str], depth_stack: deque,
                       single_exploit: bool, single_label: bool, neighbours: set[str] = None):
    """
    Depth first search algorithm for generating graphs
    Parameters:
        exploited_services:
        exploited_vulnerabilities:
        services:
        subnets:
        exploitable_vulnerabilities:
        sub_labels:
        depth_stack:
        single_exploit:
        single_label:
        neighbours:
    """
    
    (exploited_service, current_privilege) = depth_stack.pop()
    
    if neighbours is None:
        neighbours = TopologyLayer.get_neighbours(services, subnets, exploited_service)
    
    for neighbour in neighbours:
        
        if neighbour == 'outside':
            continue
        
        neighbour_exploitable = exploitable_vulnerabilities[neighbour]['pre_values']
        neighbour_post = exploitable_vulnerabilities[neighbour]['post_conditions']
        
        for neighbour_pre_condition in range(0, current_privilege + 1):
            for vulnerability in neighbour_exploitable[neighbour_pre_condition]:
                
                neighbour_post_condition = neighbour_post[vulnerability]
                start_attack_vertex = (exploited_service, VulnerabilityLayer.get_privilege_str(current_privilege))
                end_attack_vertex = (neighbour, VulnerabilityLayer.get_privilege_str(neighbour_post_condition))
                
                if single_exploit:
                    if neighbour not in exploited_services:
                        exploited_services.add(neighbour)
                        add_attack_edge(sub_labels, start_attack_vertex, end_attack_vertex, vulnerability)
                        depth_stack.append((neighbour, neighbour_pre_condition))
                
                else:
                    label = (start_attack_vertex, end_attack_vertex)
                    if label not in sub_labels or \
                            (not single_label and vulnerability not in exploited_vulnerabilities[label]):
                        
                        if label in exploited_vulnerabilities:
                            exploited_vulnerabilities[label].add(vulnerability)
                        else:
                            exploited_vulnerabilities[label] = {vulnerability}
                        
                        add_attack_edge(sub_labels, start_attack_vertex, end_attack_vertex, vulnerability)
                        depth_stack.append((neighbour, neighbour_pre_condition))


def add_attack_edge(sub_labels: dict[((str, str), (str, str)), str], start_attack_vertex: (str, str),
                    end_attack_vertex: (str, str), vulnerability: str):
    """
    Add an edge to the attack graph
    Parameters:
        sub_labels:
        start_attack_vertex:
        end_attack_vertex:
        vulnerability:
    """
    
    # If add_edge() is called from here, it will encounter performance issue.
    # Maybe it has some reasons with Python's deep copy mechanism.
    # So, the calling is outside of depth_first_search() with sub_graph.add_edges_from([*sub_labels.keys()])
    #
    # sub_graph.add_edge(start_attack_vertex, end_attack_vertex, weight=weight)
    
    if (start_attack_vertex, end_attack_vertex) in sub_labels:
        sub_labels[(start_attack_vertex, end_attack_vertex)] += '\n' + vulnerability
    else:
        sub_labels[(start_attack_vertex, end_attack_vertex)] = vulnerability
