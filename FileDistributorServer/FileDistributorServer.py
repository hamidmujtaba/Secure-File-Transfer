import json

from flask import Flask, request, Response, jsonify

app = Flask(__name__)

PROJECT_DIR_PATH = '/home/kernel/PycharmProjects/FileDistributorServer/'
REGISTERED_HOSTS_FILENAME = "known_hosts.json"
REGISTERED_HOSTS_FILEPATH = ''.join([PROJECT_DIR_PATH, REGISTERED_HOSTS_FILENAME])


@app.route('/publish_key', methods=['POST'])
def publish_key():
    data = request.get_json(force=True)

    if not data.get('public_key'):
        return Response("ERROR: No public key found")

    try:
        with open(REGISTERED_HOSTS_FILEPATH, 'r') as known_hosts:
            hosts_list = json.load(known_hosts)
    except (IOError, TypeError, ValueError):
        hosts_list = {request.remote_addr: data['public_key']}

    hosts_list[request.remote_addr] = data['public_key']
    with open(REGISTERED_HOSTS_FILEPATH, "w+") as known_hosts:
        json.dump(hosts_list, known_hosts, indent=4)

    return Response("PUBLISHED SUCCESSFULLY", status=201)


@app.route('/get_known_hosts', methods=['GET'])
def get_receivers():
    try:
        with open(REGISTERED_HOSTS_FILEPATH, 'r') as known_hosts:
            hosts_list = json.load(known_hosts)
    except (IOError, TypeError, ValueError):
        return Response("NO REGISTERED HOSTS FOUND", status=404)

    # del hosts_list[request.remote_addr]
    resp = jsonify(hosts_list)
    resp.status_code = 200
    return resp


if __name__ == '__main__':
    app.run()
