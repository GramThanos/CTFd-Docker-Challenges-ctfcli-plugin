#!/usr/bin/env python3
# Plugin for CTFcli
from types import MethodType
from ctfcli.utils.challenge import (
	load_challenge,
	load_installed_challenges,
)
from ctfcli.utils.config import generate_session
from pathlib import Path
import click
import re
import os
import json
import base64
import requests

def build_docker(challenge, path):
	docker_info = re.split(r"\/|\\|\:", challenge["extra"]["docker_image"])

	if len(docker_info) != 3:
		click.secho(
			f'Invalid docker_image value "{challenge["extra"]["docker_image"]}" for the challenge "{challenge["name"]}".',
			fg="red",
		)
		return False

	s = generate_session()
	docker_tar = os.path.join(os.path.dirname(path), challenge["deploy"]["docker_challenges"])
	with open(docker_tar, 'rb') as f:
		docker_tar_base64 = base64.b64encode(f.read())

	r = s.post('/api/v1/docker_challenges/image-build', allow_redirects=False, stream=True, timeout=(5*60), json={
		'repo': docker_info[0],
		'category': docker_info[1],
		'name': docker_info[2],

		'file': docker_tar_base64
	})
	if not r.status_code == 200:
		return False

	success = False
	for line in r.iter_lines():
		if line:
			try:
				j = json.loads(line.decode('utf-8'))
				if 'stream' in j:
					print(j['stream'], end = '')
				elif 'status' in j:
					print(j['status'], end = '')
				elif 'aux' in j:
					success = True
					print(j['aux'], end = '')
				else:
					print('Unknown line', j)
			except Exception as e:
				print("Plugin Error", e, line.decode('utf-8'))
				pass

	return success

def docker_challenge_deploy(self, challenge=None):
	if challenge is None:
		# Get all challenges if not specifying a challenge
		config = load_config()
		challenges = dict(config["challenges"]).keys()
	else:
		challenges = [challenge]

	for challenge in challenges:
		path = Path(challenge)

		if path.name.endswith(".yml") is False:
			path = path / "challenge.yml"

		click.secho(f"Found {path}")
		challenge = load_challenge(path)

		# If not a docker challenge, continue
		if not (challenge["type"] == 'docker' or challenge["type"] == 'docker-dynamic'):
			continue

		if not challenge["extra"]["docker_image"]:
			click.secho(
				f'The docker_image value for the challenge "{challenge["name"]}" was not found.',
				fg="red",
			)
			continue

		if not challenge["deploy"]["docker_challenges"]:
			click.secho(
				f'The docker_challenges value for the challenge "{challenge["name"]}" was not found.',
				fg="red",
			)
			continue

		if challenge["deploy"]["docker_challenges"].endswith(".tar") is False:
			click.secho(
				f'The docker_challenges value for the challenge "{challenge["name"]}" is not a tar file.',
				fg="red",
			)
			continue

		docker_tar = os.path.join(os.path.dirname(path), challenge["deploy"]["docker_challenges"])
		try:
			open(docker_tar, 'rb')
		except OSError:
			click.secho(
				f'Failed to load the docker file for the challenge "{challenge["name"]}".',
				fg="red",
			)
			continue

		click.secho(f'Loaded {challenge["name"]}', fg="yellow")

		installed_challenges = load_installed_challenges()
		for c in installed_challenges:
			if c["name"] == challenge["name"]:
				break
		else:
			click.secho(
				f'Please note that challenge "{challenge["name"]}" is not installed.',
				fg="yellow",
			)

		click.secho(f'Building docker for challenge "{challenge["name"]}"', fg="yellow")
		result = build_docker(challenge=challenge, path=path)
		if result:
			click.secho(f"Success!", fg="green")
		else:
			click.secho(f"Failed!", fg="red")

def load(commands):
	plugins = commands["plugins"]
	plugins.docker_challenge_deploy = MethodType(docker_challenge_deploy, plugins)
