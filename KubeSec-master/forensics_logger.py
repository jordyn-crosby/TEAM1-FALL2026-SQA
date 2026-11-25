import logging, os

LOG_FILE = os.environ.get('KUBESEC_FORENSICS_LOG', 'forensics.log')

def get_logger(name='kubesec.forensics'):
    logger = logging.getLogger(name)
    if not logger.handlers:
        h = logging.FileHandler(LOG_FILE)
        h.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)s | %(module)s.%(funcName)s:%(lineno)d | %(message)s'))
        logger.addHandler(h)
        logger.setLevel(logging.INFO)
    return logger

def describe(x, maxlen=40):
    '''Safe summary of an argument: type + size, no content.'''
    try:
        return f'{type(x).__name__}(len={len(x)})'
    except TypeError:
        return type(x).__name__