import logging
import threading
import traceback
from queue import Empty, Queue

logger = logging.getLogger("masky")


class ThreadPool:
    def __init__(self, masky, targets, nb_threads):
        self.__masky = masky
        self.targets_queue = Queue()
        self.output_queue = Queue()
        for target in targets:
            self.targets_queue.put(target)
        self.__nb_threads = nb_threads
        self.__thread_pool = []
        self.__name_thread = ""
        self.__active = True

    def start(self):
        logger.debug(f"Initialization of the threadpool (size: {self.__nb_threads})")
        for _ in range(self.__nb_threads):
            thread = threading.Thread(target=self.__worker, daemon=True, name="")
            thread.start()
            self.__thread_pool.append(thread)

    def get_active_threads(self):
        active_threads = []
        for thread in self.__thread_pool:
            if not "thread" in thread.name.lower():
                target = thread.name.lower().strip(" ").strip("(").strip(")")
                active_threads.append(target)
        return active_threads

    def stop(self):
        self.__active = False

        for thread in self.__thread_pool:
            if not "thread" in thread.name.lower():
                thread.join()

    def __worker(self):
        while self.__active:
            target = None

            try:
                target = self.targets_queue.get()
            except Empty:
                break

            try:
                if target:
                    self.__name_thread = f"({target}) "
                    threading.current_thread().name = self.__name_thread
                    logger.debug(f"Start of target processing")
                    rslt = self.__masky.run(target)
                    self.output_queue.put(rslt)
                    logger.debug(f"End of target processing")
            except Exception as e:
                logger.error(
                    f'Masky thread processing target "{self.__name_thread}" encountered an unexpected error: "{str(e)}"\n'
                    "-------------------------- Traceback --------------------------\n"
                    f"{traceback.format_exc()}\n"
                    "---------------------------------------------------------------\n"
                    f"Please provide this output to the Masky development team\n"
                )
                self.output_queue.put(None)
