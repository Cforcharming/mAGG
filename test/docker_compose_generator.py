#!/usr/bin/env python

"""Module for generating big docker compose files."""

import os
import yaml


def generate_compose_file(times_python):
    """Function that generates the docker-compose.yml with number of samba containers."""
    
    data = {"version": "3.8",
            "networks": {"frontend": {"driver": "bridge"},
                         "backend": {"driver": "bridge"}},
            "services": {"tc": {"image": "tomcat",
                                "networks": ["frontend"],
                                "ports": ["80"]}}}
    
    for i in range(1, times_python + 1):
        name_container = "py" + str(i)
        dict_container = {"image": "python",
                          "networks": ["frontend"],
                          "tty": True}
        data["services"][name_container] = dict_container
    
    with open(os.path.join(os.getcwd(), 'docker-compose.yml'), 'w') as outfile:
        yaml.dump(data, outfile, default_flow_style=False)


generate_compose_file(5)
