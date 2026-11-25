"""Turn a rendered Windows event (XML) into a plain dictionary.

Uses the standard library XML parser. Works for any channel: Sysmon events carry named
<Data Name="..."> fields; classic events (e.g. Application) carry unnamed <Data> values,
which are kept in order under "values".
"""

import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_event_xml(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    system = root.find("e:System", NS)

    provider = system.find("e:Provider", NS)
    time_created = system.find("e:TimeCreated", NS)

    event = {
        "provider": provider.get("Name") if provider is not None else None,
        "event_id": int(system.findtext("e:EventID", default="0", namespaces=NS)),
        "record_id": int(system.findtext("e:EventRecordID", default="0", namespaces=NS)),
        "time": time_created.get("SystemTime") if time_created is not None else None,
        "computer": system.findtext("e:Computer", default=None, namespaces=NS),
        "channel": system.findtext("e:Channel", default=None, namespaces=NS),
        "data": {},
    }

    event_data = root.find("e:EventData", NS)
    if event_data is not None:
        unnamed = []
        for item in event_data.findall("e:Data", NS):
            name = item.get("Name")
            value = item.text if item.text is not None else ""
            if name:
                event["data"][name] = value
            else:
                unnamed.append(value)
        if unnamed:
            event["data"]["values"] = unnamed

    return event
