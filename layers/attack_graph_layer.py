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
Layer for manipulation of the attack graphs of networks.
Including class AttackGraphLayer
"""

import time
import networkx as nx
from collections import deque
from concurrent.futures import Executor, Future, wait
from layers.vulnerability_layer import VulnerabilityLayer


class AttackGraphLayer:
    """
    Encapsulation of attack graphs subnetworks.
    Properties:
        attack_graph: a dictionary of nx.DiGraph, where members are attack graphs for a subnet.
        
        graph_labels: labels for attack graphs, containing detailed CVE entries.
        
        vulnerability_layer: VulnerabilityLayer binding
    """
    
    def __init__(self, vulnerability_layer: VulnerabilityLayer, executor: Executor):
        """
        
        :param vulnerability_layer:
        :param executor:
        """
        self._attack_graph = dict()
        self._graph_labels = dict()
        self._executor = executor
        self._vulnerability_layer = vulnerability_layer
        
        print('Attack graphs of subnets generation started.')
        start = time.time()

        self.update_by_networks([*self._vulnerability_layer.topology_layer.networks.keys()])

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
    
    def update_by_networks(self, affected_networks: list[str]):
        """
        Update attack graphs with a list of networks
        Parameters:
            affected_networks: list of networks to update attack graph
        """
        
        futures: list[Future] = list()
        
        services = self.vulnerability_layer.topology_layer.services
        networks = self.vulnerability_layer.topology_layer.networks
        exploitable_vulnerabilities = self.vulnerability_layer.exploitable_vulnerabilities
        single_exploit = self.vulnerability_layer.config['single-exploit-per-node']
        single_label = self.vulnerability_layer.config['single-edge-label']
        
        if self._executor is not None:
            for network in affected_networks:
                future = self._executor.submit(generate_sub_graph, services, networks, network,
                                               exploitable_vulnerabilities, single_exploit, single_label)
                future.add_done_callback(update(self.attack_graph, self.graph_labels, network))
                futures.append(future)

        elif 'exposed' in affected_networks:
            composed_graph, composed_labels = generate_full_from_exposed(services, exploitable_vulnerabilities,
                                                                         networks, single_exploit, single_label)
            self.attack_graph['full'] = composed_graph
            self.graph_labels['full'] = composed_labels

        else:
            for network in affected_networks:
                sub_graph, sub_labels = \
                    generate_sub_graph(services, networks, network, exploitable_vulnerabilities,
                                       single_exploit, single_label)
                self.attack_graph[network] = sub_graph
                self.graph_labels[network] = sub_labels

        if self._executor is not None:
            wait(futures)
        
        for network in [*self.graph_labels.keys()]:
            if len(self.graph_labels[network]) == 0:
                del self.graph_labels[network]
                del self.attack_graph[network]


def update(attack_graph: dict[str, nx.DiGraph], graph_labels: dict[str, dict[((str, str), (str, str)), (str, str)]],
           network: str):
    """
    Update attack_graph and graph_labels according to future results
    Parameters:
        attack_graph:
        graph_labels:
        network:
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
        attack_graph[network] = sub_graph
        graph_labels[network] = sub_labels
    return cbs


def generate_sub_graph(services: dict[str, dict[str]], networks: dict[str, dict[str, set]], network: str,
                       exploitable_vulnerabilities: dict[str, dict[str, dict]],
                       single_exploit: bool, single_label: bool) \
        -> (nx.DiGraph, dict[((str, str), (str, str)), str]):
    """
    Generate attack graph for full connected networks.
    Parameters:
        services:
        networks:
        network:
        exploitable_vulnerabilities:
        single_exploit:
        single_label:
    Returns:
        a nx.Digraph object and its labels in dict
    """
    
    sub_graph = nx.DiGraph()
    sub_labels: dict[((str, str), (str, str)), str] = dict()
    
    gateways: set[str] = networks[network]['gateways']
    neighbours: set[str] = networks[network]['nodes']
    
    exploited_vulnerabilities: dict[(str, str), set[str]] = dict()
    
    if 'outside' in neighbours:
        gateways.add('outside')
    
    for gateway in gateways:
        
        if gateway == 'outside':
            gateway_post_privileges = {4: ['']}
        else:
            gateway_post_privileges: dict[int, list[str]] = exploitable_vulnerabilities[gateway]['post']
        
        depth_stack = deque()
        exploited_nodes: set[str] = {gateway}
        
        for current_privilege in gateway_post_privileges:
            depth_stack.append((gateway, current_privilege))
            
        while len(depth_stack) > 0:
            depth_first_search(exploited_nodes, exploited_vulnerabilities, services, networks,
                               exploitable_vulnerabilities, sub_labels, depth_stack,
                               single_exploit, single_label, neighbours)
    
    sub_graph.add_edges_from([*sub_labels.keys()])
    print(f'Generated sub attack graph for network \'{network}\'', flush=True)
    return sub_graph, sub_labels


def generate_full_from_exposed(services: dict[str, dict[str]], exploitable_vulnerabilities: dict[str, dict[str, dict]],
                               networks: dict[str, dict[str, set]], single_exploit: bool, single_label: bool) \
        -> (nx.DiGraph, dict[((str, str), (str, str)), str]):
    """
    Generate a full attack graph from exposed nodes.
    Parameters:
        services:
        exploitable_vulnerabilities:
        networks:
        single_exploit:
        single_label:
    Returns:
        a nx.Digraph object and its labels in dict
    """
    
    composed_graph = nx.DiGraph()
    composed_labels: dict[((str, str), (str, str)), str] = dict()
    
    exploited_vulnerabilities: dict[(str, str), set[str]] = dict()
    depth_stack = deque()
    depth_stack.append(('outside', 4))
    exploited_nodes: set[str] = {'outside'}

    while len(depth_stack) > 0:
        depth_first_search(exploited_nodes, exploited_vulnerabilities, services, networks, exploitable_vulnerabilities,
                           composed_labels, depth_stack, single_exploit, single_label)
    
    composed_graph.add_edges_from([*composed_labels.keys()])
    print('Generated full attack graph from outside.', flush=True)
    return composed_graph, composed_labels
    

def get_neighbours(services: dict[str, dict[str]], networks: dict[str, dict[str, set]], node: str) -> set[str]:
    """
    Get neighbours of a node
    Parameters:
        services:
        networks:
        node:
        Returns:
          A set of neighbours
    """
    
    neighbours: set[str] = set()
    if node != 'outside':
        nws = services[node]['networks']
    else:
        nws = ['exposed']
    
    for nw in nws:
        for neighbour in networks[nw]['nodes']:
            neighbours.add(neighbour)
    
    return neighbours


def depth_first_search(exploited_nodes: set[str], exploited_vulnerabilities: dict[(str, str), set[str]],
                       services: dict[str, dict[str]], networks: dict[str, dict[str, set]],
                       exploitable_vulnerabilities: dict[str, dict[str, dict]],
                       sub_labels: dict[((str, str), (str, str)), str], depth_stack: deque,
                       single_exploit: bool, single_label: bool, neighbours: set[str] = None):
    """
    Depth first search algorithm for generating graphs
    Parameters:
        exploited_nodes:
        exploited_vulnerabilities:
        services:
        networks:
        exploitable_vulnerabilities:
        sub_labels:
        depth_stack:
        single_exploit:
        single_label:
        neighbours:
    """
    
    (exploited_node, current_privilege) = depth_stack.pop()
    
    if neighbours is None:
        neighbours = get_neighbours(services, networks, exploited_node)
    
    for neighbour in neighbours:
        
        if neighbour == 'outside':
            continue
        
        neighbour_exploitable = exploitable_vulnerabilities[neighbour]['pre']
        neighbour_post = exploitable_vulnerabilities[neighbour]['postcond']
        
        for neighbour_pre_condition in range(0, current_privilege + 1):
            for vulnerability in neighbour_exploitable[neighbour_pre_condition]:
                
                neighbour_post_condition = neighbour_post[vulnerability]
                start_node = (exploited_node, VulnerabilityLayer.get_privilege_str(current_privilege))
                end_node = (neighbour, VulnerabilityLayer.get_privilege_str(neighbour_post_condition))
                
                if single_exploit:
                    if neighbour not in exploited_nodes:
                        exploited_nodes.add(neighbour)
                        add_edge(sub_labels, start_node, end_node, vulnerability)
                        depth_stack.append((neighbour, neighbour_pre_condition))
                
                else:
                    label = (start_node, end_node)
                    if label not in sub_labels or \
                            (not single_label and vulnerability not in exploited_vulnerabilities[label]):
                        
                        if label in exploited_vulnerabilities:
                            exploited_vulnerabilities[label].add(vulnerability)
                        else:
                            exploited_vulnerabilities[label] = {vulnerability}
                        
                        add_edge(sub_labels, start_node, end_node, vulnerability)
                        depth_stack.append((neighbour, neighbour_pre_condition))


def add_edge(sub_labels: dict[((str, str), (str, str)), str], start_node: (str, str),
             end_node: (str, str), vulnerability: str):
    """
    Adding an edge to the attack graph
    Parameters:
        sub_labels:
        start_node:
        end_node:
        vulnerability:
    """
    
    # If add_edge() is called from here, it will encounter performance issue.
    # Maybe it has some reasons with Python's deep copy mechanism.
    # So, the calling is outside of depth_first_search() with sub_graph.add_edges_from([*sub_labels.keys()])
    #
    # sub_graph.add_edge(start_node, end_node, weight=weight)
    
    if (start_node, end_node) in sub_labels:
        sub_labels[(start_node, end_node)] += '\n' + vulnerability
    else:
        sub_labels[(start_node, end_node)] = vulnerability
