import datetime
import logging
from database.models import Pcap, ThreatReport, StatusEnum
from src.database.utilities import *

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


BATCH_SIZE = 100
PCAP_SIZE_KEY = 'pcap_size'

MAX_RETRIES = 3  # max number of retries for a request
RETRY_DELAY = 1  # delay between retries in seconds


def create_threat_report(pcap_id, source_ip, dest_ip, protocol, timestamp, ip_count):
    report = ThreatReport(pcap_id=int(pcap_id), source_ip=source_ip, 
                          dest_ip=dest_ip, status=StatusEnum.DETECTED, 
                          protocol=protocol, ip_count=ip_count,
                          timestamp=timestamp, last_updated=datetime.datetime.now().isoformat())
    return commit_object(report)


def get_pcap(pcap_id, session):
    try:
        return session.query(Pcap).filter_by(id=pcap_id).one()
    except NoResultFound:
        raise
    except Exception as e:
        raise e


def update_pcap(pcap_id, ddos_rate, is_analised, error, prediction_time):
    session = get_session()
    pcap = get_pcap(pcap_id, session)
    logger.info(f"pcap: {pcap}")
    pcap.ddos_rate = ddos_rate
    pcap.is_analysed = is_analised
    pcap.detection_time = prediction_time
    return update_object(pcap, session)




