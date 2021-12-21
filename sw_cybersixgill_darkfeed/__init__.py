from sixgill.sixgill_feed_client import SixgillFeedClient, SixgillBaseClient
from sixgill.sixgill_utils import is_indicator
import requests
import logging
from swimlane import Swimlane
from sixgill.sixgill_constants import FeedStream


class SixgillDarkfeedBaseClass:
    def __init__(self, context):
        self.client_id = context.asset.get('client_id', '')
        self.client_secret = context.asset.get('client_secret', '')
        self.verify = context.asset.get('verify_ssl', False)
        http_proxy = context.asset.get('http_proxy')
        self.swimlane_access_token = context.asset.get('swimlane_access_token', '')
        self.swimlane_app_name = context.asset.get('swimlane_app_name', '')
        session = requests.Session()
        session.proxies = {} if not http_proxy else http_proxy
        self.proxy = session
        self.channel_id = '9edd89168582842d84430bac51a06eb3'

    def auth_test(self):
        """checks to see if asset inputs are valid."""
        access_token = SixgillBaseClient(self.client_id, self.client_secret, self.channel_id, session=self.proxy,
                                         verify=True).get_access_token()
        return access_token

    # def swimlane_auth_test(self, url):
    #     """checks to see if asset inputs are valid."""
    #     Swimlane(url, access_token=self.swimlane_access_token, verify_ssl=self.verify)


class SixgillAPIRequests(SixgillDarkfeedBaseClass):

    def __init__(self, context):
        super(SixgillAPIRequests, self).__init__(context)
        self.sixgill_darkfeed_client = SixgillFeedClient(self.client_id, self.client_secret, self.channel_id,
                                                         FeedStream.DARKFEED, verify=True, bulk_size=2000)

    def get_dark_feed(self):
        raw_response = self.sixgill_darkfeed_client.get_bundle()
        return list(filter(is_indicator, raw_response.get("objects", [])))

    def darkfeed_ack(self):
        self.sixgill_darkfeed_client.commit_indicators()


class SwimlaneAPIRequests(SixgillDarkfeedBaseClass):

    def __init__(self, context):
        super(SwimlaneAPIRequests, self).__init__(context)
        self.swimlane_client = Swimlane(context.config['InternalSwimlaneUrl'], access_token=self.swimlane_access_token,
                                        verify_ssl=self.verify)

    def delete_record_from_swimlane(self, search_id):
        try:
            app = self.swimlane_client.apps.get(name=self.swimlane_app_name)
            records = app.records.search(('Cybersixgill Indicator Id', 'equals', search_id))
            for record in records:
                record.delete()
        except Exception:
            logging.exception("Unable to delete duplicate/revoked records from swimlane")


class SwimlaneDarkFeedFields:

    def __init__(self, description, sixgill_actor, sixgill_confidence, sixgill_feed_name, sixgill_post_id,
                 sixgill_post_title, sixgill_severity, sixgill_source, sixgill_indicator_id, labels, created, modified,
                 valid_from, indicator_type, indicator_value, virus_total_positive_rate,
                 virus_total_url, mitre_description, mitre_tactic, mitre_tactic_id, mitre_tactic_url,
                 mitre_technique, mitre_technique_id, mitre_technique_url, language):
        self.description = description
        self.cybersixgill_actor = sixgill_actor
        self.cybersixgill_confidence = sixgill_confidence
        self.cybersixgill_feed_name = sixgill_feed_name
        self.cybersixgill_post_id = sixgill_post_id
        self.cybersixgill_post_title = sixgill_post_title
        self.cybersixgill_severity = sixgill_severity
        self.cybersixgill_source = sixgill_source
        self.cybersixgill_indicator_id = sixgill_indicator_id
        self.labels = labels
        self.modified = modified
        self.created = created
        self.valid_from = valid_from
        self.indicator_type = indicator_type
        self.indicator_value = indicator_value
        self.virus_total_positive_rate = virus_total_positive_rate
        self.virus_total_url = virus_total_url
        self.mitre_descriptions = mitre_description
        self.mitre_tactics = mitre_tactic
        self.mitre_tactic_ids = mitre_tactic_id
        self.mitre_tactic_urls = mitre_tactic_url
        self.mitre_techniques = mitre_technique
        self.mitre_technique_ids = mitre_technique_id
        self.mitre_technique_urls = mitre_technique_url
        self.language = language