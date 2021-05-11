# -*- coding: utf-8 -*-

import os
import binascii
import requests
import almdrlib
import time
import json

def add_scan_result(session, url, scanner, scope, deployment_id, asset_id, snapshot_id, result):
    content_type = "application/json",
    metadata = {
        "scanner": scanner,
        "scanner_scope": scope,
        "asset_id": asset_id,
        "environment_id": deployment_id,
        "scan_policy_snapshot_id": snapshot_id,
        "timestamp": int(time.time()),
        "content_type": content_type
    }

    payload = {
        "metadata": json.dumps(metadata),
        "result": json.dumps(result)
    }

    data, content_type = _encode_multipart_formdata(payload)
    headers = {
        "x-aims-auth-token": session.token,
        "content-type": content_type,
        "content-length": str(len(data)),
    }
    return requests.post(url, headers = headers, data = data)


def _encode_multipart_formdata(fields):
    boundary = binascii.hexlify(os.urandom(16)).decode('ascii')
    body = (
        "".join("--%s\r\n"
                "Content-Disposition: form-data; name=\"%s\"\r\nContent-Type: application/json\r\n"
                "\r\n"
                "%s\r\n" % (boundary, field, value)
                for field, value in fields.items()) +
        "--%s--\r\n" % boundary
    )
    content_type = "multipart/form-data; boundary=%s" % boundary
    return body, content_type

