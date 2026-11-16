import datetime
import logging
import sys


class ColoredFormatter(logging.Formatter):
    COLORS = {
        # cyan
        "DEBUG": "\033[36m",
        # green
        "INFO": "\033[32m",
        # yellow
        "WARNING": "\033[33m\033[1m",
        # red
        "ERROR": "\033[31m\033[1m",
        # bright red
        "CRITICAL": "\033[1m\033[41m",
    }
    RESET = "\033[0m"

    def __init__(self, fmt=None, datefmt=None, use_color=True):
        super().__init__(fmt, datefmt)
        self.use_color = use_color

    def formatTime(self, record, datefmt=None):
        return datetime.datetime.fromtimestamp(record.created).strftime(
            datefmt or "%Y-%m-%d %H:%M:%S.%f"
        )

    def format(self, record):
        if not self.use_color:
            return super().format(record)

        levelname = record.levelname
        color = self.COLORS.get(levelname)
        if color:
            record.levelname = f"{color}{levelname}{self.RESET}"

        try:
            return super().format(record)
        finally:
            record.levelname = levelname


#   Log parameters
logger_name = "Diag_script"
logger_default_level = logging.DEBUG
# logger_default_level = logging.INFO
logger_fmt = "[%(asctime)s %(levelname)s %(filename)s:%(lineno)d] %(message)s"
logger_datefmt = "%Y-%m-%d %H:%M:%S.%f"

#   Initialize logger
logger = logging.getLogger(logger_name)
logger.setLevel(logger_default_level)

#   Initialize console handler for log printing
logger_console_handler = logging.StreamHandler()
logger_console_handler.setFormatter(
    ColoredFormatter(logger_fmt, logger_datefmt, use_color=sys.stderr.isatty())
)
logger.addHandler(logger_console_handler)
