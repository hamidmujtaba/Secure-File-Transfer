import json

from flask import Flask, request, Response, jsonify

app = Flask(__name__)

PROJECT_DIR_PATH = '/home/kernel/PycharmProjects/Secure File Sharing/FileDistributorServer/'
REGISTERED_HOSTS_FILENAME = "file_distribution_db.json"
REGISTERED_HOSTS_FILEPATH = ''.join([PROJECT_DIR_PATH, REGISTERED_HOSTS_FILENAME])


@app.route('/publish_key', methods=['POST'])
def publish_key():
    data = request.get_json(force=True)

    if not (data.get('public_key') or data.get('client_id')):
        return Response("ERROR: Invalid Request Parameters")

    try:
        with open(REGISTERED_HOSTS_FILEPATH, 'r') as file_distribution_db:
            clients_dict = json.load(file_distribution_db)
            clients_dict[data['client_id']] = {"public_key": data['public_key'],
                                               "ip": request.remote_addr,
                                               "downloadable_files": []}

    except (IOError, TypeError, ValueError):
        clients_dict = {data['client_id']: {"public_key": data['public_key'], "ip": request.remote_addr,
                                            "downloadable_files": []}}

    with open(REGISTERED_HOSTS_FILEPATH, "w+") as file_distribution_db:
        json.dump(clients_dict, file_distribution_db, indent=4)

    return Response("PUBLISHED SUCCESSFULLY", status=201)


@app.route('/get_known_hosts', methods=['GET'])
def get_receivers():
    try:
        with open(REGISTERED_HOSTS_FILEPATH, 'r') as file_distribution_db:
            clients_data = json.load(file_distribution_db)
    except (IOError, TypeError, ValueError):
        return Response("NO REGISTERED HOSTS FOUND", status=404)

    hosts_list = [(k, v["public_key"]) for k, v in clients_data.items()]
    resp = jsonify(hosts_list)
    resp.status_code = 200
    return resp


@app.route('/upload_file', methods=['POST'])
def upload_file():
    data = request.get_json(force=True)
    if not (data.get('receiver') or data.get('filename') or data.get('file_contents')):
        return Response("INVALID_REQUEST", status=400)

    try:
        with open(REGISTERED_HOSTS_FILEPATH, 'r') as file_distribution_db:
            clients_data = json.load(file_distribution_db)
    except (IOError, TypeError, ValueError):
        return Response("NO REGISTERED HOSTS FOUND", status=404)

    clients_data[data['receiver']]['downloadable_files'].append({'filename': data['filename'],
                                                               'file_contents': data['file_contents'],
                                                               'sender': request.remote_addr})

    with open(REGISTERED_HOSTS_FILEPATH, "w+") as file_distribution_db:
        json.dump(clients_data, file_distribution_db, indent=4)

    return Response("UPLOAD_SUCCESSFUL", status=200)


@app.route('/get_files', methods=['GET'])
def get_files():
    try:
        with open(REGISTERED_HOSTS_FILEPATH, 'r') as file_distribution_db:
            clients_data = json.load(file_distribution_db)
    except (IOError, TypeError, ValueError):
        return Response("NO REGISTERED HOSTS FOUND", status=404)

    identity = request.args.get('identity')
    if not (identity or clients_data.get(identity)):
        return Response(status=400)

    if not clients_data[identity]['downloadable_files']:
        return Response(status=204)

    resp = jsonify(clients_data[identity]['downloadable_files'])
    resp.status_code = 200
    return resp


if __name__ == '__main__':
    app.run()
