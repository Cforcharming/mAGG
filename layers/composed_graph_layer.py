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
from layers.attack_graph_layer import AttackGraphLayer


class ComposedGraphLayer:
    
    def __init__(self, attack_graph_layer: AttackGraphLayer):
        
        self._composed_graph = None
        self._composed_labels = None
        self._attack_graph_layer = attack_graph_layer
        self.get_graph_compose()
        self.__remove_redundant()
        
    @property
    def composed_graph(self) -> nx.DiGraph:
        return self._composed_graph
    
    @property
    def composed_labels(self) -> dict[((str, str), (str, str)), str]:
        return self._composed_labels
    
    @composed_graph.setter
    def composed_graph(self, composed_graph: nx.DiGraph):
        self._composed_graph = composed_graph
    
    @composed_labels.setter
    def composed_labels(self, composed_labels: dict[((str, str), (str, str)), str]):
        self._composed_labels = composed_labels
    
    def get_graph_compose(self):
        """This functions prints graph properties."""
    
        dcg = time.time()
        print('Composing attack graphs from subnets started.')
        self._composed_labels = dict()
        
        if 'full' not in self._attack_graph_layer.attack_graph:
        
            try:
                self.composed_graph = nx.compose_all([*self._attack_graph_layer.attack_graph.values()])
                
                for network in self._attack_graph_layer.graph_labels:
                    self.composed_labels |= self._attack_graph_layer.graph_labels[network]
            except ValueError:
                self.composed_graph = nx.DiGraph()
        
        else:
            self.composed_graph = self._attack_graph_layer.attack_graph['full']
            self.composed_labels = self._attack_graph_layer.graph_labels['full']
        
        dcg = time.time() - dcg
        print('Time for composing subnets:', dcg, 'seconds.')
    
    # noinspection PyCallingNonCallable
    def __remove_redundant(self):
        
        depth_delete_stack = deque()
        
        for node in self.composed_graph:
            
            if self.composed_graph.in_degree(node) == 0:
                (name, privilege) = node
                if name != 'outside':
                    depth_delete_stack.append(node)
        
        while len(depth_delete_stack) > 0:
            self.__depth_first_remove(depth_delete_stack)
    
    # noinspection PyCallingNonCallable
    def __depth_first_remove(self, depth_delete_stack: deque):
    
        node_to_remove = depth_delete_stack.pop()
        edges_to_remove = []
        end_nodes = set()
        
        out_edges = self.composed_graph.out_edges(node_to_remove)
        for out_edge in out_edges:
            (start_node, end_node) = out_edge
            edges_to_remove.append(out_edge)
            del self.composed_labels[out_edge]
            end_nodes.add(end_node)
        
        for end_node in end_nodes:
            
            if self.composed_graph.in_degree(end_node) == 0:
                depth_delete_stack.append(end_node)
    
        self.composed_graph.remove_node(node_to_remove)
