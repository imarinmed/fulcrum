import logging
import structlog

def setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    
    # Suppress noisy library logs
    logging.getLogger("googleapiclient").setLevel(logging.ERROR)
    logging.getLogger("google.auth").setLevel(logging.ERROR)
    
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
    )
