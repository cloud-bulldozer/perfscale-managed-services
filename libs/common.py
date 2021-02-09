import elasticsearch
import logging
import time
import os
import errno

def _connect_to_es(es_url, insecure):
    if es_url.startswith('https://'):
        import urllib3
        import ssl
        ssl_ctx = ssl.create_default_context()
        if insecure:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        es = elasticsearch.Elasticsearch([es_url], send_get_body_as='POST',
                                         ssl_context=ssl_ctx, use_ssl=True)
    elif es_url.startswith('http://'):
        es = elasticsearch.Elasticsearch([es_url], send_get_body_as='POST')
    else:
        logging.error('Invalid ES URL: %s' % es_url)
        exit(1)
    return es

def _index_result(es,index,metadata,ignoreMetadata,index_retry):
    my_doc = _buildDoc(metadata, ignoreMetadata)

    logging.debug('Document to be uploaded to ES:')
    logging.debug(my_doc)

    for attempt in range(index_retry + 1):
        try:
            time.sleep(5 * attempt)
            logging.info('Attempting to upload (Attempt: %d) information to ES server with index %s' % (attempt, index))
            es.index(index=index, body=my_doc)
        except Exception as e:
            logging.error(e)
            logging.error('Failed to upload to ES, waiting %d seconds for next upload retry' % (5 * (attempt + 1)))
        else:
            logging.debug('ES upload successful for cluster id %s' % my_doc['cluster_id'])
            return 0
    else:
        logging.error('Reached the maximun number of retries: %d, ES upload failed for %s' % (index_retry, my_doc['cluster_id']))
        return 1

def _buildDoc(metadata, ignoreMetadata):

    my_doc = {}
    my_doc = _getValue(metadata, ignoreMetadata)
    return my_doc

def _getValue(value, ignoreMetadata):
    # Parse booleans
    if isinstance(value, bool):
        return bool(value)

    # Parse int
    try:
        return int(value)
    except Exception as e:
        logging.debug('value {} is not an int {}'.format(value, e))

    # Parse floats
    # By default it was being truncated to int
    try:
        return int(float(value))
    except Exception as e:
        logging.debug('value {} is not an int {}'.format(value, e))

    # Parse strings
    if isinstance(value, str):
        return str(value)

    # Parse a dictionary
    elif isinstance(value, dict):
        dictionary = {}
        for key in value:
            if key not in ignoreMetadata:
                val = value[key]
                key = key.replace('-', '_').replace(' ', '_').lower()
                v = _getValue(val, ignoreMetadata)
                dictionary[key] = v
        return dictionary
    return

def _create_path(my_path):
    try:
        logging.info('Create directory %s if it does not exist' % my_path)
        os.makedirs(my_path, exist_ok=True)
    except OSError as e:
        if e.errno != errno.EEXIST:
            logging.error(e)
            exit(1)
