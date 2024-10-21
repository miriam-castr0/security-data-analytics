import os, sys
import unittest
from unittest.mock import MagicMock, patch
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if src_path not in sys.path:
    sys.path.append(src_path)
ACCURACY_THRESHOLD = os.environ.get('ACC_THRESHOLD')
from src.services.feedback_optimization_engine import FeedbackOptimizationEngine  # Replace with correct import path

class TestFeedbackOptimizationEngine(unittest.TestCase):


    def test_check_model_method(self):
        
        mock_rasp = MagicMock()

        
        engine = FeedbackOptimizationEngine(mock_rasp)

        # Call method
        results = engine.check_model()

        # Verify if there is at least one result
        self.assertGreater(len(results), 0)

        for result in results:
            self.assertGreaterEqual(result[1], float(ACCURACY_THRESHOLD))  # verify ACC


