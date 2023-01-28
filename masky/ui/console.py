import logging
from pathlib import Path
from queue import Empty
from ..utils.threadpool import ThreadPool
from ..core import Masky
from ..utils.toolbox import is_valid_output_folder
from .options import Options, get_cli_args

GET_QUEUE_TIMEOUT = 0.01
logger = logging.getLogger("masky")


class Console:
    def __init__(self):
        self.__tp = None
        self.__opts = None

    def __save_pfx(self, output_folder, user):
        try:
            pfx_path = Path(output_folder / f"{user.domain}-{user.name}.pfx")
            with open(pfx_path, "wb+") as fd:
                fd.write(user.pfx)
        except:
            pass

    def __save_ccache(self, output_folder, user):
        try:
            ccache_path = Path(output_folder / f"{user.domain}-{user.name}.ccache")
            with open(ccache_path, "wb+") as fd:
                fd.write(user.ccache)
        except:
            pass

    def __save_hashes(self, hashes_file, user):
        try:
            nt_entry = f"{user.domain}\\{user.name}:{user.nt_hash}"
            if not hashes_file.is_file():
                hashes_file.touch()
            with open(hashes_file, "r+") as fd:
                if not nt_entry in fd.read():
                    fd.write(f"{nt_entry}\n")
        except Exception as e:
            pass

    def __process_results(self, rslt):
        if not rslt or not rslt.users:
            return False
        output_folder = Path(self.__opts.output)
        hashes_file = output_folder / "hashes.txt"
        if not is_valid_output_folder(self.__opts.output):
            output_folder.mkdir(parents=True, exist_ok=True)
        for user in rslt.users:
            if not self.__opts.no_hash and user.nt_hash:
                self.__save_hashes(hashes_file, user)
            if not self.__opts.no_pfx and user.pfx:
                self.__save_pfx(output_folder, user)
            if not self.__opts.no_ccache and user.ccache:
                self.__save_ccache(output_folder, user)
        return True

    def __run(self):
        masky = Masky(
            ca=self.__opts.ca,
            dc_ip=self.__opts.dc_ip,
            template=self.__opts.template,
            domain=self.__opts.domain,
            user=self.__opts.user,
            password=self.__opts.password,
            hashes=self.__opts.hashes,
            kerberos=self.__opts.kerberos,
            stealth=self.__opts.stealth,
            exe_path=self.__opts.exe_path,
            file_args=self.__opts.file_args,
            quiet=False,
        )
        self.__tp = ThreadPool(masky, self.__opts.targets, self.__opts.threads)
        self.__tp.start()
        processed_targets = 0
        while processed_targets != len(self.__opts.targets):
            try:
                rslt = self.__tp.output_queue.get(timeout=GET_QUEUE_TIMEOUT)
                self.__process_results(rslt)
                processed_targets += 1
            except Empty:
                pass

    def start(self):
        cli_parser = get_cli_args()
        self.__opts = Options(cli_parser)
        if not self.__opts.process():
            logger.error("The provided options are invalids")
            return False
        self.__run()
        return True

    def stop(self):
        try:
            active_threads = self.__tp.get_active_threads()
            self.__tp.stop()
            while not self.__tp.output_queue.empty():
                rslt = self.__tp.output_queue.get()
                try:
                    self.__process_results(rslt)
                except Exception as e:
                    logger.warn(f"Fail to process results ({str(e)})")
        except KeyboardInterrupt:
            logger.warn(
                "Multiple interruption signals were triggered, Masky is forced to exit without properly cleaning currently processed servers"
            )
            logger.warn(
                f"The following servers may be cleaned manually: {active_threads}"
            )
