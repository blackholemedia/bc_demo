import logging
from datetime import date

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
TODAY = date.today().strftime('%Y-%m-%d')
logging.basicConfig(filename='{}.log'.format(TODAY), level=logging.DEBUG, format=LOG_FORMAT)
