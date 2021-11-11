from sw_cybersixgill_darkfeed import SixgillDarkfeedBaseClass


class SwMain(SixgillDarkfeedBaseClass):

    def execute(self):
        try:
            self.auth_test()
            # self.swimlane_auth_test()
        except Exception as e:
            return {'successful': False, 'errorMessage': str(e)}
        return {'successful': True}

