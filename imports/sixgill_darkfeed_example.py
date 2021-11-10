from sw_cybersixgill_darkfeed import SixgillAPIRequests, SwimlaneDarkFeedFields, SwimlaneAPIRequests
import re

class SwMain(SixgillAPIRequests, SwimlaneAPIRequests):

    def __init__(self, context):
        super(SwMain, self).__init__(context)

    def execute(self):
        """
        This method results parses darkfeed data from cybersixgill as per swimlane
        """
        dark_feed = []
        darkfeed_data = self.get_dark_feed()
        for indicator in darkfeed_data:
            if not indicator.get('revoked', False):
                self.parse_darkfeed(indicator, dark_feed)
            else:
                indicator_id = indicator.get('id', '')
                self.delete_record_from_swimlane(search_id=indicator_id)

        # Acknowledge dark feed data received to sixgill after the parsing is done
        self.darkfeed_ack()
        return dark_feed

    def parse_darkfeed(self, indicator, dark_feed):
        """
        This method parses each indicator from darkfeed
        @param indicator:
        @type indicator:
        @param dark_feed:
        @type dark_feed:
        """
        post_id = f"https://portal.cybersixgill.com/#/search?q=_id:{indicator.get('sixgill_postid', '')}" \
            if indicator.get('sixgill_postid') else ''
        indicators_list, indicator_type = self.sixgill_get_sixgill_pattern_type(indicator)

        for each_indicator in indicators_list:
            if indicator_type == "file":
                temp_indicator_type = f"file-{each_indicator.get('Type')}"
            else:
                temp_indicator_type = indicator_type
            indicator_value = each_indicator.get('Value')

            raw_response = self.parse_swimlane_fields(indicator, post_id, temp_indicator_type, indicator_value,
                                                      dark_feed)

            dark_feed.append(raw_response)

    def parse_swimlane_fields(self, indicator, post_id, indicator_type, indicator_value, dark_feed):

        virustotal_positive_rate = self.extract_external_reference_field(indicator, 'VirusTotal', 'positive_rate')
        virustotal_url = self.extract_external_reference_field(indicator, 'VirusTotal', 'url')
        mitre_description = self.extract_external_reference_field(indicator, 'mitre-attack', 'description')
        mitre_attack_tactic = self.extract_external_reference_field(indicator, 'mitre-attack', 'mitre_attack_tactic')
        mitre_attack_tactic_id = self.extract_external_reference_field(indicator, 'mitre-attack',
                                                                       'mitre_attack_tactic_id')
        mitre_attack_tactic_url = self.extract_external_reference_field(indicator, 'mitre-attack',
                                                                        'mitre_attack_tactic_url')
        mitre_attack_technique = self.extract_external_reference_field(indicator, 'mitre-attack',
                                                                       'mitre_attack_technique')
        mitre_attack_technique_id = self.extract_external_reference_field(indicator, 'mitre-attack',
                                                                          'mitre_attack_technique_id')
        mitre_attack_technique_url = self.extract_external_reference_field(indicator, 'mitre-attack',
                                                                           'mitre_attack_technique_url')

        raw_response = SwimlaneDarkFeedFields(indicator.get('description', ''), indicator.get('sixgill_actor', ''),
                                              indicator.get('sixgill_confidence', ''),
                                              indicator.get('sixgill_feedname', ''),
                                              post_id, indicator.get('sixgill_posttitle', ''),
                                              indicator.get('sixgill_severity', ''),
                                              indicator.get('sixgill_source', ''),
                                              indicator.get('id', ''), indicator.get('labels', ''),
                                              indicator.get('created', ''),
                                              indicator.get('modified', ''), indicator.get('valid_from', ''),
                                              indicator_type,
                                              indicator_value,
                                              virustotal_positive_rate,
                                              virustotal_url, mitre_description, mitre_attack_tactic,
                                              mitre_attack_tactic_id,
                                              mitre_attack_tactic_url, mitre_attack_technique,
                                              mitre_attack_technique_id,
                                              mitre_attack_technique_url, indicator.get('lang', '')).__dict__

        return raw_response

    @staticmethod
    def sixgill_get_sixgill_pattern_type(indicator):
        """This method parses the 'Pattern' of the darkfeed to retrieve the IOC's

        Arguments:
            indicator - Cybersixgill Darkfeed Indicator

        Returns:
            list -- Key, Value pair of the retrived IOC's
        """
        stix_regex_parser = re.compile(
            r"([\w-]+?):(\w.+?) (?:[!><]?=|IN|MATCHES|LIKE) '(.*?)' *[OR|AND|FOLLOWEDBY]?")
        indicator_list = []
        final_indicator_type = ''
        if "pattern" in indicator:
            for indicator_type, sub_type, value in stix_regex_parser.findall(indicator.get("pattern")):
                indicator_dict = {}
                if indicator_type == "file":
                    if "MD5" in sub_type:
                        indicator_dict.update({"Type": "MD5", "Value": value})
                    if "SHA-1" in sub_type:
                        indicator_dict.update({"Type": "SHA-1", "Value": value})
                    if "SHA-256" in sub_type:
                        indicator_dict.update({"Type": "SHA-256", "Value": value})
                    indicator_list.append(indicator_dict)
                    final_indicator_type = indicator_type
                elif indicator_type == "url":
                    indicator_dict.update({"Type": "URL", "Value": value})
                    indicator_list.append(indicator_dict)
                    final_indicator_type = indicator_type
                elif indicator_type == "ipv4-addr":
                    indicator_dict.update({"Type": "IP Address", "Value": value})
                    indicator_list.append(indicator_dict)
                    final_indicator_type = indicator_type
                elif indicator_type == "domain":
                    indicator_dict.update({"Type": "DOMAIN", "Value": value})
                    indicator_list.append(indicator_dict)
                    final_indicator_type = indicator_type
        return indicator_list, final_indicator_type

    @staticmethod
    def extract_external_reference_field(stix2obj, source_name, field_to_extract):
        for reference in stix2obj.get("external_reference", []):
            if reference.get("source_name") == source_name:
                return reference.get(field_to_extract, None)
