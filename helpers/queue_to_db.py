from datetime import datetime
from helpers import common_strings
from helpers.mongo_connection import db


def reputation_response_db_addition(value, output):
    db['domain-reputation'].find_one_and_update({common_strings.strings['mongo_value']: value},
                                                {'$set': {'status': common_strings.strings['status_finished'],
                                                          'timeStamp': datetime.utcnow(), 'output': output}})
