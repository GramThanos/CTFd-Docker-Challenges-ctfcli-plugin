# A [ctfcli](https://github.com/CTFd/ctfcli) plugin for the Docker Challenges plugin for CTFd

A plugin to build docker images of docker challenges directly from ctfcli.

## Install plugin

Install from the github repository.
```
ctf plugins install https://github.com/GramThanos/CTFd-Docker-Challenges-ctfcli-plugin.git
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

If you want to test it to a server of yours:
```
ctf plugins docker_challenge_test "web/example-challenge" user@192.168.1.10
```
