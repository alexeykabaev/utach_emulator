import logging
import sys

form = logging.Formatter(fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%d-%b-%y %H:%M:%S")
log_handler = logging.StreamHandler(sys.stdout)
log_handler.setFormatter(form)
logging.root.setLevel(logging.INFO)
logging.root.addHandler(log_handler)

