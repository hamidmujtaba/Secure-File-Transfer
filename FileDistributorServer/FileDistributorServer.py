import json

from flask import Flask, request, Response, jsonify

app = Flask(__name__)

PROJECT_DIR_PATH = '/home/kernel/PycharmProjects/Secure File Sharing/FileDistributorServer/'
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
            hosts_list[request.remote_addr] = {"public_key": data['public_key'], "downloadable_files": []}

    except (IOError, TypeError, ValueError):
        hosts_list = {request.remote_addr: {"public_key": data['public_key'], "downloadable_files": []}}

    with open(REGISTERED_HOSTS_FILEPATH, "w+") as known_hosts:
        json.dump(hosts_list, known_hosts, indent=4)

    return Response("PUBLISHED SUCCESSFULLY", status=201)


@app.route('/get_known_hosts', methods=['GET'])
def get_receivers():
    try:
        with open(REGISTERED_HOSTS_FILEPATH, 'r') as known_hosts:
            hosts_data = json.load(known_hosts)
    except (IOError, TypeError, ValueError):
        return Response("NO REGISTERED HOSTS FOUND", status=404)

    hosts_list = list((k, v["public_key"]) for k, v in hosts_data.items())
    # del hosts_list[request.remote_addr]
    resp = jsonify(hosts_list)
    resp.status_code = 200
    return resp


@app.route('/upload_file', methods=['POST'])
def upload_file():
    data = request.get_json(force=True)
    if not (data.get('receiver') or data.get('filename') or data.get('file_contents')):
        return Response("INVALID_REQUEST", status=400)

    try:
        with open(REGISTERED_HOSTS_FILEPATH, 'r') as known_hosts:
            hosts_data = json.load(known_hosts)
    except (IOError, TypeError, ValueError):
        return Response("NO REGISTERED HOSTS FOUND", status=404)

    hosts_data[data['receiver']]['downloadable_files'].append({'filename': data['filename'],
                                                               'file_contents': data['file_contents'],
                                                               'sender': request.remote_addr})

    with open(REGISTERED_HOSTS_FILEPATH, "w+") as known_hosts:
        json.dump(hosts_data, known_hosts, indent=4)

    return Response("UPLOAD_SUCCESSFUL", status=200)


@app.route('/get_files', methods=['GET'])
def get_files():
    try:
        with open(REGISTERED_HOSTS_FILEPATH, 'r') as known_hosts:
            hosts_data = json.load(known_hosts)
    except (IOError, TypeError, ValueError):
        return Response("NO REGISTERED HOSTS FOUND", status=404)

    print hosts_data

if __name__ == '__main__':
    app.run()
