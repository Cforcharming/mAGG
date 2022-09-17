#!/usr/bin/env python

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
Main module that builds a pipeline for multiple experiments. For details, please see main.ipydb
"""

import os
import sys
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor

from layers.vulnerability_layer import ClairctlVulnerabilityLayer
from layers.topology_layer import DockerComposeTopologyLayer
from layers.composed_graph_layer import ComposedGraphLayer
from layers.merged_graph_layer import MergedGraphLayer
from layers.attack_graph_layer import AttackGraphLayer

from mio import wrapper

__version__ = '1.2'


def main(argv):
    """
    Main function responsible for running the attack graph generations pipeline for multiple graphs.
    Parameters:
        argv: sys.argv
    """
    config, experiments = wrapper.init(argv)
    
    concurrency = config['nums-of-processes']
    executor = None
    if concurrency > 0:
        executor = ProcessPoolExecutor(concurrency, mp.get_context('forkserver'))
    
    attack_vectors = ClairctlVulnerabilityLayer.get_attack_vectors(config['nvd-feed-path'], executor)
    
    for experiment in experiments:
        experiment_dir, result_dir = wrapper.create_directories(experiment, config)
        do_experiment(experiment_dir, result_dir, config, attack_vectors, executor)
    
    return 0


def do_experiment(experiment_dir: str, result_dir: str, config: dict, attack_vectors: dict[str, dict[str]],
                  executor: ProcessPoolExecutor):
    """
    Creating layers of one experiment directory, then test honeypot deployments.
    Parameters:
        experiment_dir:
        result_dir:
        config: config.yml file in form of dictionary
        attack_vectors: result of VulnerabilityLayer.get_attack_vectors()
        executor: concurrent.futures.Executor, default: None
    """
    
    print(f'\n\n\n\n\n******************************{os.path.basename(experiment_dir)}******************************')
    
    # get topology layer
    match topology_type := config['topology-type']:
        case 'docker-compose':
            topology_layer = DockerComposeTopologyLayer(experiment_dir)
        case _:
            raise ValueError(f'Topology type {topology_type} not implemented, '
                             f'please feel free to open Issue or PR on GitHub.')
    
    # get vulnerability layer
    match vulnerability_type := config['vulnerability-type']:
        case 'clairctl':
            vulnerability_layer = ClairctlVulnerabilityLayer(topology_layer, config, attack_vectors)
        case _:
            raise ValueError(f'Vulnerability type {vulnerability_type} not implemented, '
                             f'please feel free to open Issue or PR on GitHub.')
    
    # get attack graph layer
    attack_graph_layer = AttackGraphLayer(vulnerability_layer, executor)
    
    # get composed graph layer
    composed_graph_layer = ComposedGraphLayer(attack_graph_layer)
    
    # get merged graph layer
    merged_graph_layer = MergedGraphLayer(composed_graph_layer)
    
    # Printing time summary of the attack graph generation.
    wrapper.print_summary(merged_graph_layer)

    if config['deploy-honeypots']:
        to = config['honeypot-destination']
        minimum = 0
        path_counts = merged_graph_layer.gen_defence_list(to)
        
        n1 = merged_graph_layer.service_probabilities.copy()
        merged_graph_layer.deploy_honeypot(path_counts, minimum)
        merged_graph_layer.compare_rates(n1, merged_graph_layer.service_probabilities, to)
    
    if config['draw-graphs']:
        # draw graphs
        wrapper.visualise(merged_graph_layer, result_dir, 0)


if __name__ == '__main__':
    # All magics start from here...
    sys.exit(main(sys.argv))
