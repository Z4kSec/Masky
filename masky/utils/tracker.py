class Tracker:
    def __init__(self):
        self.svc_name = None
        self.agent_filename = None
        self.output_filename = None
        self.error_filename = None
        self.args_filename = None
        self.svc_cleaning_success = True
        self.files_cleaning_success = True
        self.nb_hijacked_users = 0
        self.last_error_msg = None
