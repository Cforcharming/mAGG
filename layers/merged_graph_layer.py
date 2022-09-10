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
from layers.vulnerability_layer import VulnerabilityLayer
from layers.attack_graph_layer import AttackGraphLayer
from layers.topology_layer import TopologyLayer
import networkx as nx


class MergedGraphLayer:
    
    def __init__(self, topology_layer: TopologyLayer, vulnerability_layer: VulnerabilityLayer,
                 attack_graph_layer: AttackGraphLayer, composed_graph_layer: ComposedGraphLayer):
        
        self._merged_graph = nx.DiGraph()
        self._topology_layer = topology_layer
        self._vulnerability_layer = vulnerability_layer
        self._attack_graph_layer = attack_graph_layer
        self._composed_graph_layer = composed_graph_layer
        self.merge()
    
    @property
    def merged_graph(self) -> nx.DiGraph:
        return self._merged_graph
    
    @merged_graph.setter
    def merged_graph(self, merged_graph: nx.DiGraph):
        self._merged_graph = merged_graph
        
    def merge(self):
        # TODO
        pass
    
    def gen_defence_list(self, to_n: str, from_n='outside') -> dict[str, int]:
        
        path_counts: dict[str, int] = dict()
        for gateway in self._topology_layer.gateway_nodes:
            degree: int = self._topology_layer.topology_graph.degree(gateway)
            path_counts[gateway] = degree
        
        for node in nx.shortest_path(self.merged_graph, from_n, to_n):
            if node in path_counts:
                path_counts[node] = path_counts[node] + 1
            else:
                path_counts[node] = 1
        
        return path_counts
    
    def deploy_honeypot(self, path_counts, minimum):
        
        affected_networks = []
        
        image = 'nginx'
        self._vulnerability_layer.add_image(image)
        
        h = 0
        for name in path_counts:
            if path_counts[name] < minimum:
                break
            honeypot_name = 'honey-' + str(h)
            self._topology_layer.networks[honeypot_name] = {'nodes': {name, honeypot_name}, 'gateways': {name}}
            new_service = {'image': image, 'networks': [honeypot_name]}
            self._topology_layer.add_service(new_service, honeypot_name)
            h += 1

        self._attack_graph_layer.update_by_networks(affected_networks)
        self._composed_graph_layer.get_graph_compose()
        self.merge()
