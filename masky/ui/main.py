import logging
import traceback
import sys
from ..utils.logger import load_custom_logger
from .console import Console

VERSION = "0.2.0"
logger = logging.getLogger("masky")


def print_banner():
    print(
        f"""
  __  __           _          
 |  \/  | __ _ ___| | ___   _ 
 | |\/| |/ _` / __| |/ / | | |
 | |  | | (_| \__ \   <| |_| |
 |_|  |_|\__,_|___/_|\_\\__,  |
  v{VERSION}                 |___/ 
    """
    )


def ctrlc_handler(exception, cli):
    logger.warn("Interruption received, wait for Masky to finish running scans... ")
    try:
        if cli:
            cli.stop()
    except:
        pass
    logger.info("Exiting...")
    sys.exit(0)


def main():
    try:
        cli = None
        print_banner()
        load_custom_logger()
        cli = Console()
        cli.start()
    except KeyboardInterrupt as e:
        ctrlc_handler(e, cli)
    except Exception as e:
        logger.error(
            f'Masky encountered an unexpected error: "{str(e)}"\n'
            "-------------------------- Traceback --------------------------\n"
            f"{traceback.format_exc()}\n"
            "---------------------------------------------------------------\n"
            f"Please provide this output to the Masky development team\n"
        )
    logger.info("Exiting...")


if __name__ == "__main__":
    main()
