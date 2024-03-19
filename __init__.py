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
import sys
import json
import base64
import requests
import subprocess


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
	if r.status_code == 404:
		r = s.post('/api/v1/docker_challenges/images/build', allow_redirects=False, stream=True, timeout=(5*60), json={
			'repo': docker_info[0],
			'category': docker_info[1],
			'name': docker_info[2],

			'file': docker_tar_base64
		})

	if not r.status_code == 200:
		#print(r.text)
		#print(r.status_code)
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


def docker_challenge_test(self, challenge=None, creds=None, command=None):
	if challenge is None:
		# Error
		click.secho(f'No docker challenge selected.', fg="red")
		return

	path = Path(challenge)

	if path.name.endswith(".yml") is False:
		path = path / "challenge.yml"

	click.secho(f"Found {path}")
	challenge = load_challenge(path)

	# If not a docker challenge, continue
	if not (challenge["type"] == 'docker' or challenge["type"] == 'docker-dynamic'):
		# Error
		click.secho(f'The challenge "{challenge["name"]}" is not a docker challenge.', fg="red")
		return

	if not challenge["extra"]["docker_image"]:
		click.secho(f'The docker_image value for the challenge "{challenge["name"]}" was not found.', fg="red",)
		return

	if not challenge["deploy"]["docker_challenges"]:
		click.secho(f'The docker_challenges value for the challenge "{challenge["name"]}" was not found.', fg="red")
		return

	if challenge["deploy"]["docker_challenges"].endswith(".tar") is False:
		click.secho(f'The docker_challenges value for the challenge "{challenge["name"]}" is not a tar file.', fg="red")
		return

	docker_tar = os.path.join(os.path.dirname(path), challenge["deploy"]["docker_challenges"])
	try:
		open(docker_tar, 'rb')
	except OSError:
		click.secho(f'Failed to load the docker file for the challenge "{challenge["name"]}".', fg="red")
		return

	click.secho(f'Loaded {challenge["name"]}', fg="yellow")

	# Connection info
	ssh_id = creds if creds else None
	ssh_domain = 'direct.labs.play-with-docker.com'

	# Ask for id for play with docker
	if not creds:
		click.secho(f'Instructions:\n1. Open https://labs.play-with-docker.com/\n2. Click start\n3. Click Add new session\n4. Copy and paste here your session ssh command', fg="yellow")
	else:
		click.secho(f'Connection info "{creds}" will be used', fg="yellow")
	
	try:
		if not ssh_id:
			ssh_id = input("ssh command: ").strip()
		if ' ' in ssh_id:
			ssh_id = ssh_id.split(' ')[1].strip()
		if '@' in ssh_id:
			ssh_domain = ssh_id.split('@')[1].strip()
			ssh_id = ssh_id.split('@')[0].strip()
		assert bool(re.match(r'^[a-zA-Z0-9_-]+$', ssh_id))
	except Exception as e:
		print(e)
		click.secho(f'Failed get play with docker ssh id.', fg="red")
		return


	if command:
		import pty;
		pty.spawn(['/bin/bash', '-c', f"ssh -t {ssh_id}@{ssh_domain} '{command}'"])
		click.secho(f'Exiting...', fg="yellow")
		return


	try:
		click.secho(f'Clearing running docker tests...', fg="yellow")
		result = subprocess.run(f"ssh -t {ssh_id}@{ssh_domain} 'docker stop docker_challenge_test && docker rm docker_challenge_test'", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, check=False)
		click.secho(result.stdout.strip(), fg="bright_black")

		click.secho(f'Uploading docker challenge image...', fg="yellow")
		result = subprocess.run(f"scp {docker_tar} {ssh_id}@{ssh_domain}:~/docker-challenge-test.tar", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, check=False)
		click.secho(result.stdout.strip(), fg="bright_black")

		click.secho(f'Building docker challenge image...', fg="yellow")
		result = subprocess.run(f"ssh -t {ssh_id}@{ssh_domain} 'cat ~/docker-challenge-test.tar | docker build - -t docker_challenge_test'", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, check=True)
		click.secho(result.stdout.strip(), fg="bright_black")

		click.secho(f'Running docker container for the challenge...', fg="yellow")
		result = subprocess.run(f"ssh -t {ssh_id}@{ssh_domain} 'docker run -P --name docker_challenge_test -d docker_challenge_test'", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, check=True)
		click.secho(result.stdout.strip(), fg="bright_black")

		click.secho(f'Getting info...', fg="yellow")
		command = 'docker inspect --format "{{ .NetworkSettings.Ports }}" docker_challenge_test'
		result = subprocess.run(f"ssh -t {ssh_id}@{ssh_domain} '{command}'", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, check=True)
		info = result.stdout.strip()
		match = re.search(r'\{0\.0\.0\.0 (\d+)\}', info)
		if match:
			port = match.group(1)
			click.secho(f'Container is listening on port {port}', fg="bright_black")
			if ssh_domain == 'direct.labs.play-with-docker.com':
				click.secho(f'Container is available at http://{ssh_id}-{port}.direct.labs.play-with-docker.com/', fg="bright_black")
			click.secho(f'HTTP   : http://{ssh_domain}:{port}/', fg="bright_black")
			click.secho(f'HTTPS  : https://{ssh_domain}:{port}/', fg="bright_black")
			click.secho(f'NETCAT : nc {ssh_domain} {port}', fg="bright_black")
		elif info == 'map[]':
			click.secho(f'Container is not running.', fg="red")
			result = subprocess.run(f"ssh -t {ssh_id}@{ssh_domain} 'docker logs docker_challenge_test'", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, check=True)
			click.secho(result.stdout.strip(), fg="bright_black")
		else:
			click.secho(f'Unable to decode info.', fg="bright_black")
			click.secho(result.stdout, fg="bright_black")

		click.secho(f"Success!", fg="green")
	except subprocess.CalledProcessError as e:
		click.secho(e.stdout.strip(), fg="bright_black")
		click.secho(e.stderr.strip(), fg="red")
		click.secho(f'Failed!', fg="red")
		return
	except Exception as e:
		print(e)
		click.secho(f'Failed!', fg="red")
		return


def load(commands):
	plugins = commands["plugins"]
	plugins.docker_challenge_deploy = MethodType(docker_challenge_deploy, plugins)
	plugins.docker_challenge_test = MethodType(docker_challenge_test, plugins)
