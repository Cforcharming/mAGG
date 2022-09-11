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
Layer for manipulation of the topology of systems.
Including abstract class TopologyLayer
"""

import os
import yaml
import time
import networkx as nx


class TopologyLayer:
    """
    Encapsulation of physical topology of a network.
    
    Properties:
        networks: in shape of {'net1':{'nodes':set(), 'gateways', set()}}
        
        services: in shape of {'service1': {'nodes': set(), 'networks': [], 'gateways':set()}}
        
        gateway_nodes: in shape of {'g1', 'g2'}
        
        topology_graph: a networkx.Graph object with services as nodes and connections as edges.
        
        gateway_graph: a networkx.Graph object with subnets as nodes and gateways as edges.
        
        gateway_graph_labels: a dictionary label used for gateway_graph, like {('net1', 'net2'): 'g1'}
    """

    def __init__(self, example_folder: str):
        """
        Initialise a topology layer
        Parameters:
            example_folder: str, The folder containing topology structures and configuration files.
        """
        
        self._networks = None
        self._services = None
        self._gateway_nodes = set()
        self._topology_graph = nx.Graph()
        self._gateway_graph = nx.Graph()
        self._gateway_graph_labels = dict()
        self._example_folder = example_folder

        dt = self.__parse_topology()
        dg = self.__create_graphs()
        print('\nTime for initialising topology layer:', dt + dg, 'seconds.')
    
    @property
    def networks(self) -> dict[str, dict[str, set]]:
        """
        Returns:
             networks: in shape of {'net1':{'nodes':set(), 'gateways', set()}}
        """
        return self._networks
    
    @property
    def services(self) -> dict[str, dict[str]]:
        """
        Returns:
            services: in shape of {'service1': {'nodes': set(), 'networks': [], 'gateways':set()}}
        """
        return self._services
    
    @property
    def gateway_nodes(self) -> set[str]:
        """
        Returns:
            gateway_nodes: in shape of {'g1', 'g2'}
        """
        return self._gateway_nodes
    
    @property
    def topology_graph(self) -> nx.Graph:
        """
        Returns:
            topology_graph: a networkx.Graph object with services as nodes and connections as edges.
        """
        return self._topology_graph
    
    @property
    def gateway_graph(self) -> nx.Graph:
        """
        Returns:
            gateway_graph: a networkx.Graph object with subnets as nodes and gateways as edges.
        """
        return self._gateway_graph
    
    @property
    def gateway_graph_labels(self) -> dict[(str, str), str]:
        """
        Returns:
            gateway_graph_labels: a dictionary label used for gateway_graph, like {('net1', 'net2'): 'g1'}
        """
        return self._gateway_graph_labels
    
    @networks.setter
    def networks(self,  networks: dict[str, dict[str, set]]):
        self._networks = networks

    @services.setter
    def services(self, services: dict[str, dict[str]]):
        self._services = services
    
    @gateway_nodes.setter
    def gateway_nodes(self, gateway_nodes: set[str]):
        self._gateway_nodes = gateway_nodes
    
    @topology_graph.setter
    def topology_graph(self, topology_graph: nx.Graph):
        self._topology_graph = topology_graph
    
    @gateway_graph.setter
    def gateway_graph(self, gateway_graph: nx.Graph):
        self._gateway_graph = gateway_graph
    
    @gateway_graph_labels.setter
    def gateway_graph_labels(self, gateway_graph_labels: dict[(str, str), str]):
        self._gateway_graph_labels = gateway_graph_labels
    
    def add_service(self, new_service: dict[str], name: str):
        """
        Add a service to topology
        
        Parameters:
            new_service: new service to add
            name: name of new service
        Raises:
            ValueError if name of service is already in
        """
        if name in self.services:
            raise ValueError('Name\'' + name + '\' already defined in topology.')
        self.update_service(new_service, name)
    
    def update_service(self, new_service: dict[str], name: str):
        """
        Update a service to topology
        
        Parameters:
            new_service: new service to add
            name: name of new service
        Raises:
            ValueError if name of service is not in
        """
        
        if name in self.services:
            del self[name]
        
        self.services[name] = new_service
        self.__add_service_networks(name)
        self.__add_service_to_graph(name)
    
    def __delitem__(self, name: str):
        """
        Delete a service by name from the topology.
        
        For example:
        
        del topology['x']
        
        deletes node 'x' from the graph.
        
        Parameters:
            name: a service to delete by name
        """
        service_to_delete = self.services[name]
        network_to_delete = service_to_delete['networks']
        
        for n in network_to_delete:
            network = self.networks[n]
            network['nodes'].remove(name)
            if name in network['gateways']:
                network['gateways'].remove(name)
        
        self.topology_graph.remove_node(name)
        if self.gateway_graph.has_node(name):
            self.gateway_graph.remove_node(name)
            self.gateway_nodes.remove(name)
            for (u, v) in self.gateway_graph_labels.copy():
                if u == name or v == name:
                    del self.gateway_graph_labels[(u, v)]
        
        if name in self.gateway_nodes:
            self.gateway_nodes.remove(name)
        del self.services[name]

    def __parse_folder(self):
        """
        It returns a dictionary of all services defined in docker-compose.yml
        """
    
        docker_compose = self.__read_docker_compose_file()
    
        self.services = docker_compose.get("services", dict())
        self.networks = docker_compose.get('networks', dict())
    
        for network in self.networks:
            self.networks[network] = {'nodes': set(), 'gateways': set()}
    
        self.networks['exposed'] = {'nodes': {'outside'}, 'gateways': set()}
    
    def __parse_topology(self) -> float:
        """
        Parsing topology from a folder.
        Returns:
            dt: time for topology generation
        """
        
        time_start = time.time()
        print("Topology parsing started.")
        
        self.__parse_folder()
        
        for name in self.services:
            self.__add_service_networks(name)
        
        dt = time.time() - time_start
        print('Time for parsing topology:', dt, 'seconds.')
        return dt
    
    def __create_graphs(self) -> float:
        """
        Create Property topology_graph and gateway_graph
        Returns:
            dg: time for graph generation
        """
        
        start = time.time()
        print("Topology graph creation started.")
        
        for name in self.services:
            self.__add_service_to_graph(name)
        
        dg = time.time() - start
        print('Time for creating topology graphs:', dg, 'seconds.')
        return dg

    def __add_service_networks(self, name: str):
        """
        Add a specific service to its belonging networks.
        Parameters:
            name: the service to add provided by name
        """
        
        service = self.services[name]
        
        service_network: list = service['networks']
    
        if len(service_network) >= 1:
        
            if len(service_network) > 1:
                self.gateway_nodes.add(name)
        
            for sn in service_network:
            
                if sn in self.networks:
                    self.networks[sn]['nodes'].add(name)
                    if len(service_network) > 1:
                        self.networks[sn]['gateways'].add(name)
                else:
                    if len(service_network) > 1:
                        self.networks[sn] = {'nodes': {name}, 'gateways': {name}}
                    else:
                        self.networks[sn] = {'nodes': {name}, 'gateways': set()}
            
                if "ports" in service.keys():
                    self.networks[sn]['gateways'].add(name)
                    self.gateway_nodes.add(name)
    
        if "ports" in service.keys():
            service['networks'].append('exposed')
            self.networks['exposed']['nodes'].add(name)
            self.networks['exposed']['gateways'].add(name)
            self.gateway_nodes.add(name)
    
    def __add_service_to_graph(self, name: str):
        """
        Add a specific service to its belonging graphs.
        Parameters:
            name: the service to add provided by name
        """
        
        self.topology_graph.add_node(name)
        
        service = self.services[name]
        service_network = service['networks']
        for sn in service_network:
            neighbours = self.networks[sn]['nodes']
            for neighbour in neighbours:
                if neighbour != name:
                    self.topology_graph.add_edge(name, neighbour)
        
            if len(service_network) > 1:
                for s2 in service_network:
                    if sn != s2:
                        self.gateway_graph.add_edge(sn, s2)
                        self.gateway_graph_labels[(sn, s2)] = name
        
            if "ports" in service.keys():
                self.topology_graph.add_edge('outside', name)
                if sn != 'exposed':
                    self.gateway_graph.add_edge('exposed', sn)
                    self.gateway_graph_labels[('exposed', sn)] = name
    
    def __read_docker_compose_file(self) -> dict[str]:
        """
        Parsing docker-compose.yml into a dictionary.
        Returns:
             a dictionary of docker-compose.yml
        """
    
        with open(os.path.join(self._example_folder, "docker-compose.yml"), "r") as compose_file:
            docker_compose_file = yaml.full_load(compose_file)
    
        return docker_compose_file
