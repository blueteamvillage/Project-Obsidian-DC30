# Jupyter Notebook Install

Quick resources for initial setup.

## Visual Studio Code

1. Install Code
1. Install extensions: python, jupyter notebook
1. Install msticpy
  * from inside code and notebook: `%pip install msticpy`

https://code.visualstudio.com/docs/datascience/jupyter-notebooks

## Linux Command-Line

```
apt install python3 python3-pip
pip install jupyterlab msticpy
# or
pip install -r requirements.txt
```

Run
```
jupyter lab
```

## Macos Command-Line

with [Homebrew](https://brew.sh/)

```
brew python3
pip install jupyterlab msticpy
# or
pip install -r requirements.txt
```

Run
```
jupyter lab
```

## Windows

* Use native python
  * https://www.python.org/downloads/windows/
* Use WSL - And Linux section after
  * https://docs.microsoft.com/en-us/windows/wsl/install
  * https://www.windowscentral.com/how-install-wsl2-windows-10
* Use Cygwin
  * https://www.cygwin.com/install.html

Run
```
jupyter-notebook
python -m notebook
python -m jupyter lab
```

Known issue with pip: TBD link

## Docker

* https://hub.docker.com/r/jupyter/datascience-notebook

## Hosted jupyter

* https://jupyter.org/try
* https://mybinder.org/
* https://noteable.io/
* https://colab.research.google.com/
* https://docs.microsoft.com/en-us/azure/machine-learning/how-to-run-jupyter-notebooks
* https://github.com/features/codespaces

## Msticpy

* https://msticpy.readthedocs.io/en/latest/getting_started/Installing.html
