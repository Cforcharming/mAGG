#!/usr/bin/env python

"""Module for generating big docker compose files."""

import os
import yaml
import shutil


def generate_full_conn(j):
    """Function that generates the docker-compose.yml with number of samba containers."""

    example_folder = 'examples/full-conn/' + str(j) + '-example/'
    
    if not os.path.exists(j):
        os.makedirs(j)
    
    data = {"version": "3.8",
            "networks": {"frontend": {}},
            "services": {"tc": {"image": "tomcat",
                                "networks": ["frontend"],
                                "ports": ["80"]}}}
    
    for i in range(1, j + 1):
        name_container = "py" + str(i)
        dict_container = {"image": "python",
                          "networks": ["frontend"]}
        data["services"][name_container] = dict_container
    
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/tomcat-vulnerabilities.json'), example_folder)
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/python-vulnerabilities.json'), example_folder)
    
    with open(os.path.join(example_folder, 'docker-compose.yml'), 'w') as outfile:
        yaml.dump(data, outfile, default_flow_style=False)
