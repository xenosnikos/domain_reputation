import os
from flask_restful import Resource, reqparse, request, inputs
import json

from helpers import utils
from helpers import queue_to_db
from helpers import common_strings
from helpers import logging_setup
from helpers import auth_check
from helpers.requests_retry import retry_session

"""
API Call: POST
Endpoint: https://{url}/v2/domain-reputation?force=true
Body: {
        "value": "securityvue.com"
      }
Authorization: Needed
"""

request_args = reqparse.RequestParser()
request_args.add_argument(common_strings.strings['key_value'], help=common_strings.strings['domain_required'],
                          required=True)
request_args.add_argument(common_strings.strings['input_force'], type=inputs.boolean, required=False, default=False)

logger = logging_setup.initialize(common_strings.strings['domain-reputation'], r'C:\Users\SanthoshSonti\Documents\git\domainreputation\logs\domain-reputation_api.log')


class DomainReputation(Resource):

    @staticmethod
    def post():
        args = request_args.parse_args()

        value = args[common_strings.strings['key_value']]

        logger.debug(f"Expansion scan request received for {value}")

        auth = request.headers.get(common_strings.strings['auth'])

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            logger.debug(f"Unauthenticated Expansion scan request received for {value}")
            return authentication, 401

        if not utils.validate_domain(value):  # if regex doesn't match throw a 400
            logger.debug(f"Domain that doesn't match regex request received - {value}")
            return {
                       common_strings.strings['message']: f"{value}" + common_strings.strings['invalid_domain']
                   }, 400

        # if domain doesn't resolve into an IP, throw a 400 as domain doesn't exist in the internet
        try:
            ip = utils.resolve_domain_ip(value)
        except Exception as e:
            logger.debug(f"Domain that doesn't resolve to an IP requested - {value, e}")
            return {
                       common_strings.strings['message']: f"{value}" + common_strings.strings[
                           'unresolved_domain_ip']
                   }, 400

        if args[common_strings.strings['input_force']]:
            force = True
        else:
            force = False

        # based on force - either gives data back from database or gets a True status back to continue with a fresh scan
        check = utils.check_force(value, force, collection=common_strings.strings['domain-reputation'],
                                  timeframe=int(os.environ.get('DATABASE_LOOK_BACK_TIME')))

        # if a scan is already requested/in-process, we send a 202 indicating that we are working on it
        if check == common_strings.strings['status_running'] or check == common_strings.strings['status_queued']:
            return {'status': check}, 202
        # if database has an entry with results, send it
        elif type(check) == dict and check['status'] == common_strings.strings['status_finished']:
            logger.debug(f"domain reputation scan response sent for {value} from database lookup")
            return check['output'], 200
        else:
            # mark in db that the scan is queued
            utils.mark_db_request(value, status=common_strings.strings['status_queued'],
                                  collection=common_strings.strings['domain-reputation'])
            output = {common_strings.strings['key_value']: value, common_strings.strings['key_ip']: ip}
            utils.mark_db_request(value, status=common_strings.strings['status_running'],
                                  collection=common_strings.strings['domain-reputation'])

            # calling api with retries and backoff_factor
            try:
                session = retry_session()
                resp = session.get(
                    f"{os.environ.get('WHOISXML_API')}?apiKey={os.environ.get('API_KEY_WHOIS_XML')}"
                    f"&domainName={value}")
            except Exception as e:
                logger.critical(f'Exception occurred in whoisxml endpoint {e}')
                resp = None

            logger.debug(f"WHOISXML reputation scan for {value} is complete")

            if resp is not None and resp.status_code == 200:
                output.update(json.loads(resp.text))
            else:
                # if we error due to WHOISXML or any other reason, send a 503 with WHOISXML status code as message or a
                # generic error message
                if resp is not None:
                    logger.debug(f"WHOISXML failed for {value} with {resp.status_code}")
                    return resp.status_code, 503
                else:
                    logger.debug(f"Cannot call WHOISXML for {value}")
                    return 'domain reputation is currently unavailable', 503

            try:
                queue_to_db.reputation_response_db_addition(value, output)
            except Exception as e:
                logger.critical(common_strings.strings['database_issue'], e)

            logger.debug(f"WHOISXML response for {value} is sent performing a new scan")
            return output, 200
