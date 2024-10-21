
import os, sys
import unittest

tests_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if tests_path not in sys.path:
    sys.path.append(tests_path)

# Import the test modules
from tests.services.test_alert_module import TestAlertModule
from tests.services.test_feedback_optimization_engine import TestFeedbackOptimizationEngine
from tests.services.test_pcap_file_reconstructor import TestPcapFileReconstructor

# Load the test suites from the test modules
suite1 = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlertModule)
suite2 = unittest.defaultTestLoader.loadTestsFromTestCase(TestFeedbackOptimizationEngine)
suite3 = unittest.defaultTestLoader.loadTestsFromTestCase(TestPcapFileReconstructor)
# Combine the test suites into a single test suite
all_tests = unittest.TestSuite([suite1, suite2, suite3])

# Run the combined test suite
runner = unittest.TextTestRunner()
runner.run(all_tests)
