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
        subnets: in shape of {'net1':{'services':set(), 'gateways', set()}}
        
        services: in shape of {'service1': {'services': set(), 'subnets': [], 'gateways':set()}}
        
        gateway_services: in shape of {'g1', 'g2'}
        
        topology_graph: a nx.Graph object with services as services and connections as edges.
        
        gateway_graph: a nx.Graph object with subnets as services and gateways as edges.
        
        gateway_graph_labels: a dictionary label used for gateway_graph, like {('net1', 'net2'): 'g1'}
    """

    def __init__(self, example_folder: str):
        """
        Initialise a topology layer
        Parameters:
            example_folder: str, The folder containing topology structures and configuration files.
        """
        
        self._subnets = None
        self._services = None
        self._gateway_services = set()
        self._topology_graph = nx.Graph()
        self._gateway_graph = nx.Graph()
        self._gateway_graph_labels = dict()
        self._example_folder = example_folder
        
        dt = self.__parse_topology()
        dg = self.__create_graphs()
        print(f'Time for initialising topology layer: {dt + dg} seconds.')
    
    @property
    def subnets(self) -> dict[str, dict[str, set]]:
        """
        Returns:
             subnets: in shape of {'net1':{'services':set(), 'gateways', set()}}
        """
        return self._subnets
    
    @property
    def services(self) -> dict[str, dict[str]]:
        """
        Returns:
            services: in shape of {'service1': {'services': set(), 'subnets': [], 'gateways':set()}}
        """
        return self._services
    
    @property
    def gateway_services(self) -> set[str]:
        """
        Returns:
            gateway_services: in shape of {'g1', 'g2'}
        """
        return self._gateway_services
    
    @property
    def topology_graph(self) -> nx.Graph:
        """
        Returns:
            topology_graph: a nx.Graph object with services as services and connections as edges.
        """
        return self._topology_graph
    
    @property
    def gateway_graph(self) -> nx.Graph:
        """
        Returns:
            gateway_graph: a nx.Graph object with subnets as services and gateways as edges.
        """
        return self._gateway_graph
    
    @property
    def gateway_graph_labels(self) -> dict[(str, str), str]:
        """
        Returns:
            gateway_graph_labels: a dictionary label used for gateway_graph, like {('net1', 'net2'): 'g1'}
        """
        return self._gateway_graph_labels
    
    @property
    def example_folder(self) -> str:
        return self._example_folder
    
    @subnets.setter
    def subnets(self,  subnets: dict[str, dict[str, set]]):
        self._subnets = subnets

    @services.setter
    def services(self, services: dict[str, dict[str]]):
        self._services = services
    
    @gateway_services.setter
    def gateway_services(self, gateway_services: set[str]):
        self._gateway_services = gateway_services
    
    @topology_graph.setter
    def topology_graph(self, topology_graph: nx.Graph):
        self._topology_graph = topology_graph
    
    @gateway_graph.setter
    def gateway_graph(self, gateway_graph: nx.Graph):
        self._gateway_graph = gateway_graph
    
    @gateway_graph_labels.setter
    def gateway_graph_labels(self, gateway_graph_labels: dict[(str, str), str]):
        self._gateway_graph_labels = gateway_graph_labels
        
    @example_folder.setter
    def example_folder(self, example_folder: str):
        self._example_folder = example_folder
    
    def __setitem__(self, name: str, new_service: dict[str]):
        """
        Update a service to topology
        
        Parameters:
            new_service: new service to add
            name: name of new service
        """
        
        self.services[name] = new_service
        self.__add_service_subnets(name)
        self.__add_service_to_graph(name)
    
    def __delitem__(self, name: str):
        """
        Delete a service by name from the topology.
        
        For example:
        
        del topology['x']
        
        deletes service 'x' from the graph.
        
        Parameters:
            name: a service to delete by name
        """
        service_to_delete = self.services[name]
        subnet_to_delete = service_to_delete['subnets']
        
        for n in subnet_to_delete:
            subnet = self.subnets[n]
            subnet['services'].remove(name)
            if name in subnet['gateways']:
                subnet['gateways'].remove(name)
        
        self.topology_graph.remove_node(name)
        
        if name in self.gateway_services:
            self.gateway_services.remove(name)
            for (u, v) in self.gateway_graph_labels.copy():
                if self.gateway_graph_labels[(u, v)] == name:
                    if self.gateway_graph.has_edge(u, v):
                        self.gateway_graph.remove_edge(u, v)
                    del self.gateway_graph_labels[(u, v)]
        
        for service in list(self.gateway_graph.nodes):
            if self.gateway_graph.degree(service) == 0:
                self.gateway_graph.remove_node(service)
        
        del self.services[name]
    
    @staticmethod
    def get_neighbours(services: dict[str, dict[str]], subnets: dict[str, dict[str, set]], service: str) -> set[str]:
        """
        Get neighbours of a service
        Parameters:
            services:
            subnets:
            service:
            Returns:
              A set of neighbours
        """
    
        neighbours: set[str] = set()
        if service != 'outside':
            nws = services[service]['subnets']
        else:
            nws = ['exposed']
    
        for nw in nws:
            for neighbour in subnets[nw]['services']:
                neighbours.add(neighbour)
    
        return neighbours
    
    def __parse_folder(self):
        """
        It returns a dictionary of all services defined in docker-compose.yml
        """
    
        docker_compose = self.__read_docker_compose_file()
        
        self.services = docker_compose.get('services', dict())
        self.subnets = docker_compose.get('networks', dict())
    
        for subnet in self.subnets:
            self.subnets[subnet] = {'services': set(), 'gateways': set()}
        
        for service in self.services:
            subnet = self.services[service]['networks']
            self.services[service]['subnets'] = subnet
            del self.services[service]['networks']
        
        self.subnets['exposed'] = {'services': {'outside'}, 'gateways': set()}
    
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
            self.__add_service_subnets(name)
        
        dt = time.time() - time_start
        print(f'Time for parsing topology: {dt} seconds.')
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
        print(f'Time for creating topology graphs: {dg} seconds.')
        return dg

    def __add_service_subnets(self, name: str):
        """
        Add a specific service to its belonging subnets.
        Parameters:
            name: the service to add provided by name
        """
        
        service = self.services[name]
        
        service_subnet: list = service['subnets']
    
        if len(service_subnet) >= 1:
        
            if len(service_subnet) > 1:
                self.gateway_services.add(name)
        
            for sn in service_subnet:
            
                if sn in self.subnets:
                    self.subnets[sn]['services'].add(name)
                    if len(service_subnet) > 1:
                        self.subnets[sn]['gateways'].add(name)
                else:
                    if len(service_subnet) > 1:
                        self.subnets[sn] = {'services': {name}, 'gateways': {name}}
                    else:
                        self.subnets[sn] = {'services': {name}, 'gateways': set()}
            
                if 'ports' in service.keys():
                    self.subnets[sn]['gateways'].add(name)
                    self.gateway_services.add(name)
    
        if 'ports' in service.keys():
            service['subnets'].append('exposed')
            self.subnets['exposed']['services'].add(name)
            self.subnets['exposed']['gateways'].add(name)
            self.gateway_services.add(name)
    
    def __add_service_to_graph(self, name: str):
        """
        Add a specific service to its belonging graphs.
        Parameters:
            name: the service to add provided by name
        """
        
        self.topology_graph.add_node(name)
        
        service = self.services[name]
        service_subnet = service['subnets']
        for sn in service_subnet:
            neighbours = self.subnets[sn]['services']
            for neighbour in neighbours:
                if neighbour != name:
                    self.topology_graph.add_edge(name, neighbour)
        
            if len(service_subnet) > 1:
                for s2 in service_subnet:
                    if sn != s2:
                        self.gateway_graph.add_edge(sn, s2)
                        self.gateway_graph_labels[(sn, s2)] = name
        
            if 'ports' in service.keys():
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
    
        with open(os.path.join(self.example_folder, 'docker-compose.yml'), 'r') as compose_file:
            docker_compose_file = yaml.full_load(compose_file)
        
        return docker_compose_file
