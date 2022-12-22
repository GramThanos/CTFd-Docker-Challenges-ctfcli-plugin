# CTFd-Docker-ctfcli-Plugin

A plugin to build docker images of docker challenges directly from ctfcli.

## Install plugin

Install from the github repository.
```
ctf plugins install https://github.com/GramThanos/CTFd-Docker-ctfcli-Plugin
```

## Build a docker challenge

First install of sync a challenge the original way:
```
ctf challenge install "web/example-challenge"
```

Then ask the server to build the docker challenge image:
```
ctf plugins docker_challenge_deploy "web/example-challenge"
```
