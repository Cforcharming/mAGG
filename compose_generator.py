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

"""Module for generating big docker compose files."""

import os
import yaml
import random
import shutil


def generate_full_conn(j):
    """Function that generates the docker-compose.yml with full connections."""

    example_folder = f'examples/full-conn/{j}-example/'
    
    if not os.path.exists(example_folder):
        os.makedirs(example_folder)
    
    data = {"version": "3.8",
            "networks": {
                "frontend": {}
            },
            "services": {
                "tc": {
                    "image": "tomcat",
                    "networks": ["frontend"],
                    "ports": ["80"]
                },
                "target": {
                    "image": "mysql",
                    "networks": ["frontend"],
                }
            }
            }
    
    for i in range(1, j + 1):
        name_container = "py" + str(i)
        dict_container = {"image": "python",
                          "networks": ["frontend"]}
        data["services"][name_container] = dict_container
    
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/tomcat-vulnerabilities.json'), example_folder)
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/python-vulnerabilities.json'), example_folder)
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/mysql-vulnerabilities.json'), example_folder)
    
    with open(os.path.join(example_folder, 'docker-compose.yml'), 'w') as outfile:
        yaml.dump(data, outfile, default_flow_style=False)

    print(f'Generated dir: {example_folder}', flush=True)


def generate_designed(num_each_subnet):
    
    """Function that generates the docker-compose.yml with number of a designed structure.
Where O indicates a full connect subnet:
          O---|
      O---|   O---O---O
      |   O---|   |
  O---|   |       O---O
      |   O---|   |
      O---|   O---O---O
          O---|
  A   B   C   D   E   F
    """
    
    example_folder = f'examples/designed/{num_each_subnet}-example/'
    
    if not os.path.exists(example_folder):
        os.makedirs(example_folder)
    
    networks = {"A1": {}, "B1": {}, "B2": {}, "C1": {}, "C2": {}, "C3": {}, "C4": {}, "D1": {}, "D2": {}, "E1": {},
                "E2": {}, "E3": {}, "F1": {}, "F2": {}, "F3": {}}
    
    data = {
        "version": "3.8",
        "networks": networks,
        "services": {
            "proxy": {
                "image": "nginx",
                "networks": ["A1"],
                "ports": ["80"]
            },
            "A-B1": {
                "image": "nginx",
                "networks": ["A1", "B1"],
            },
            "A-B2": {
                "image": "nginx",
                "networks": ["A1", "B2"],
            },
            "B1-C": {
                "image": "nginx",
                "networks": ["B1", "C1", "C2"],
            },
            "B2-C": {
                "image": "nginx",
                "networks": ["B2", "C3", "C3"],
            },
            "C2-C3": {
                "image": "nginx",
                "networks": ["C2", "C3"],
            },
            "C-D1": {
                "image": "nginx",
                "networks": ["C1", "C2", "D1"],
            },
            "C-D2": {
                "image": "nginx",
                "networks": ["C3", "C4", "D2"],
            },
            "D1-E1": {
                "image": "nginx",
                "networks": ["D1", "E1"],
            },
            "D2-E3": {
                "image": "nginx",
                "networks": ["D2", "E3"],
            },
            "E1-E2": {
                "image": "nginx",
                "networks": ["E1", "E2"],
            },
            "E2-E3": {
                "image": "nginx",
                "networks": ["E2", "E3"],
            },
            "E1-F1": {
                "image": "nginx",
                "networks": ["E1", "F1"],
            },
            "E2-F2": {
                "image": "nginx",
                "networks": ["E2", "F2"],
            },
            "E3-F3": {
                "image": "nginx",
                "networks": ["E3", "F3"],
            },
            "target": {
                "image": "mysql",
                "networks": ["B2"],
            }
        }
    }
    
    py = 0
    tc = 0
    ms = 0
    app = 0
    db = 0
    
    for network in networks:
        for i in range(1, num_each_subnet):
            r = random.random()
            if r < 0.2:
                py += 1
                name_container = "python" + str(py)
                dict_container = {"image": "python",
                                  "networks": [network]}
            elif 0.2 <= r < 0.4:
                tc += 1
                name_container = "tomcat" + str(tc)
                dict_container = {"image": "tomcat",
                                  "networks": [network]}
            elif 0.4 <= r < 0.6:
                ms += 1
                name_container = "mysql" + str(ms)
                dict_container = {"image": "mysql",
                                  "networks": [network]}
            elif 0.6 <= r < 0.8:
                app += 1
                name_container = "atsea_app" + str(app)
                dict_container = {"image": "atsea_app",
                                  "networks": [network]}
            else:
                db += 1
                name_container = "atsea_db" + str(db)
                dict_container = {"image": "atsea_db",
                                  "networks": [network]}
            
            data["services"][name_container] = dict_container
    
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/tomcat-vulnerabilities.json'), example_folder)
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/python-vulnerabilities.json'), example_folder)
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/mysql-vulnerabilities.json'), example_folder)
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/nginx-vulnerabilities.json'), example_folder)
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/atsea_app-vulnerabilities.json'), example_folder)
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/atsea_db-vulnerabilities.json'), example_folder)
    
    with open(os.path.join(example_folder, 'docker-compose.yml'), 'w') as outfile:
        yaml.dump(data, outfile, default_flow_style=False)
    
    print(f'Generated dir: {example_folder}', flush=True)


if __name__ == '__main__':
    rgs = [1, 5, 10]
    for rg in rgs:
        generate_designed(rg)
        # generate_full_conn(rg)
    for rg in range(50, 1001, 50):
        generate_designed(rg)
        # generate_full_conn(rg)
