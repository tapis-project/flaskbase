"""Set up the loggers for the system."""

import logging

from .config import conf

def get_module_log_level(name: str) -> str:
    """
    Get the log level to use for this module.
    """
    # look for a log level configuration with name equal to the current module name. if one does not exist, that's fine
    # we just fall back on the "global" service log level:
    try:
        return getattr(conf, f'{name}_log_level')
    except AttributeError:
        return conf.log_level

def get_logger(name: str) -> logging.Logger:
    """
    Returns a properly configured logger.
         name (str) should be the module name.
    """
    logger = logging.getLogger(name)
    level = get_module_log_level(name)
    logger.setLevel(level)
    if not logger.hasHandlers():
        handler = logging.FileHandler(conf.log_file)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(lineno)d]'
        ))
        handler.setLevel(level)
        logger.addHandler(handler)
    logger.info("returning a logger set to level: {} for module: {}".format(level, name))
    return logger
