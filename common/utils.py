import os

# import flask.ext.restful.reqparse as reqparse
from flask import jsonify, request
from werkzeug.exceptions import ClientDisconnected
from flask_restful import Api, reqparse
from openapi_core import create_spec
import yaml

from .config import conf
from .errors import BaseTapisError

TAG = conf.version

spec_path = os.environ.get("TAPIS_API_SPEC_PATH", '/home/tapis/service/resources/openapi_v3.yml')
try:
    spec_dict = yaml.load(open(spec_path, 'r'))
    spec = create_spec(spec_dict)
except Exception as e:
    msg = f"Could not find/parse API spec file at path: {spec_path}; additional information: {e}"
    print(msg)
    raise BaseTapisError(msg)

flask_errors_dict = {
    'MethodNotAllowed': {
        'message': "Invalid HTTP method on requested resource.",
        'status': "error",
        'version': conf.version
    },
}

class RequestParser(reqparse.RequestParser):
    """Wrap reqparse to raise APIException."""

    def parse_args(self, *args, **kwargs):
        try:
            return super(RequestParser, self).parse_args(*args, **kwargs)
        except ClientDisconnected as exc:
            raise BaseTapisError(exc.data['message'], 400)


class TapisApi(Api):
    """General flask_restful Api subclass for all the Tapis APIs."""
    pass


def pretty_print(request):
    """Return whether or not to pretty print based on request"""
    if hasattr(request.args.get('pretty'), 'upper') and request.args.get('pretty').upper() == 'TRUE':
        return True
    return False

def ok(result, msg="The request was successful", request=request):
    d = {'result': result,
         'status': 'success',
         'version': TAG,
         'message': msg}
    return jsonify(d)

def error(result=None, msg="Error processing the request.", request=request):
    d = {'result': result,
         'status': 'error',
         'version': TAG,
         'message': msg}
    return jsonify(d)

def handle_error(exc):
    if isinstance(exc, BaseTapisError):
        response = error(msg=exc.msg)
        response.status_code = exc.code
        return response
    else:
        response = error(msg='Unrecognized exception type: {}. Exception: {}'.format(type(exc), exc))
        response.status_code = 500
        return response
