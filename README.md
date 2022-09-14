# mAGG: a managed multi-layer Attack Graph Generator

## Installing

---
### System Requirements

The following dependencies are needed:

* bash
* Python >= 3.10
* [Clairctl](https://github.com/jgsqware/clairctl) 
with [Clair v2.1.8](https://github.com/quay/clair/releases/tag/v2.1.8), if adding images that are not reported by us
* docker compose, if working with clairctl

Under proper configurations, all *nix systems can run mAGG. We provide a script to install dependencies:
[install_dependencies.bash](install_dependencies.bash)

Note that this script is recommended to be running on following systems:

* macOS Monterey
* Manjaro Linux
* Ubuntu 22.04 LTS
* Kali 2022.2

Other versions of the above OS, e.g. `Ubuntu 20.04 LTS`, `macOS Ventura`, 
[install_dependencies.bash](install_dependencies.bash) should also work. 
Also, the script may work on all `Arch-Based Linux` distros and `Debian Linux`.

---
### Python modules
The needed python modules are listed in [requirements.txt](requirements.txt). 
```
matplotlib >= 3.5
graphviz >= 0.20
networkx >= 2.8
jupyter >= 1.0
PyYAML >= 6.0
scipy >= 1.9
```
You can simply install them by 
```
pip install -r requirements.txt
```

Note that if you use [install_dependencies.bash](install_dependencies.bash) for system requirements,
it will create a virtualenv in directory venv with the name of your OS type. 
If your python is not configured to use venv,
then the modules will be installed globally.

For example, on Debian-based Linuxes like Ubuntu 22.04 or Kali 2022.2, you need to run
```
sudo apt install python3.10-venv
```

---
### About NVD Data Feeds
We use [NVD Data feeds](https://nvd.nist.gov/vuln/data-feeds) in format of json, and can be downloaded 
from [here](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED).
As alternative, we provide a zip file in [data/nvd-json-feed/nvdcve.zip](data/nvd-json-feed/nvdcve.zip),
and [Git LFS](https://git-lfs.github.com) is required to be installed.

---
### About Clair and Clairctl
In each run, the program will look up for json files, namely output of 'clairctl reports', 
in the same directory of `docker-compose.yml` to load CVE entries. If it is not found,
the program will call clairctl to give proper reports. If it is the case, clairctl must be installed.

[Clairctl](https://github.com/jgsqware/clairctl) is a command line interface for [Clair](https://github.com/quay/clair),
which is known as detecting CVEs in a docker container. As Clairctl stopped maintaining about five years ago,
it still can be built and used, with a specified [Clair v2.1.8](https://github.com/quay/clair/releases/tag/v2.1.8).
For detial, you need to change the tag of 'clair' in `docker-compose.yml` of your cloned Clairctl, 
then run ```docker compose up``` of clairctl

## Running

---
### main.ipynb

This is the jupyter notebook version of running, you can find the descriptions for each step,
and customise running processes on your own situations.

#### Running `main.ipynb` is the recommended way.

---
### main.py
The general usage of `main.py` is:

```
$ ./main.py [options] | [dir1 dir2 dir3..]
options:
dir1 dir2 dir3:           dirs must be in 'example-results' of data/config.yml
                          dirs must contain a valid docker-compose file, and
                          may also containing vulnerability files
                          of images in format of clair json report.

full:                     run all examples in sub directory 'full-conn'

real                      run all examples in sub directory 'designed'

-v | --version | version: show version and license

-h | --help | help:       print this message
```

The above command starts the [main.py](main.py) script and generates an attack graph for the system in the directory. 
It performs the attack graph analysis. Note that a `docker-compose.yml` is needed in the directory.

Examples are
```
$ ./main.py example
$ ./main.py atsea
$ ./main.py full
```

----
## Customising

File [data/config.yml](data/config.yml) is the main point where the attack graphs can be customized. 

The user may also modify the pre- and post-condition rules 
from which the attack graphs are created. For additional details on how to use the config file, please refer to 
the comments in the [data/config.yml](data/config.yml) file.

---
## License and Acknowledgments

Copyright 2022 Hanwen Zhang

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This project uses the tools cloned from 
[tum-i4/attack-graph-generator](https://github.com/tum-i4/attack-graph-generator)
by ibrahim *et al.* for [CVE](https://cve.org) and [NVD](https://nvd.nist.gov) data reading and parsings, 
sharing same config file settings, For details, [Clair](https://github.com/quay/clair) version 2.1.8,
and [clairctl](https://github.com/jgsqware/clairctl) are used for vulnerability exploiting.

As the names of some python files and functions remain the same, 
their implementations, algorithms and return variables are  based on our proposed methods
for topology parsings and attack graph generations.

A git branch named 'old' contains the modified original works as benchmark:

> Ibrahim, Amjad, Stevica Bozhinoski, and Alexander Pretschner.
> "Attack graph generation for microservice architecture."
> Proceedings of the 34th ACM/SIGAPP Symposium on Applied Computing. ACM, 2019.
