import threading

from src.services.feedback_optimization_engine import FeedbackOptimizationEngine
from src.services.real_time_analytics_stream_processing import RealTimeAnalyticsStreamProcessing

thread_pool = []


# TODO Put here all logic related to module

def new_thread(target_function):
    thread = threading.Thread(target=target_function)
    thread.start()
    return thread


def init_dashboard():
    global thread_pool
    real_time_analytics_engine = RealTimeAnalyticsStreamProcessing()
    feedback_engine = FeedbackOptimizationEngine(real_time_analytics_engine)

    thread_pool = [
        new_thread(real_time_analytics_engine.run_server),
        new_thread(feedback_engine.start)
    ]


def join():
    for thread in thread_pool:
        thread.join()
