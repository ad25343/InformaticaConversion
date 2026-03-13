"""
Unit tests for Customer Feed Staging Loader

Tests cover individual transformation functions and integration scenarios.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import pandas as pd
from datetime import datetime
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from customer_feed_loader import (
    apply_source_qualifier,
    apply_expression_transformation,
    StructuredLogger
)


class TestSourceQualifier(unittest.TestCase):
    """Test SQ_CUSTOMER_FEED transformation (pass-through)."""
    
    def test_pass_through_all_columns(self):
        """Verify all source columns pass through unchanged."""
        input_df = pd.DataFrame({
            'CUSTOMER_ID': ['C001', 'C002'],
            'FIRST_NAME': ['John', 'Jane'],
            'LAST_NAME': ['Doe', 'Smith'],
            'EMAIL': ['john@example.com', 'jane@example.com'],
            'PHONE': ['555-0100', '555-0101'],
            'CUSTOMER_TYPE': ['RETAIL', 'COMMERCIAL'],
            'STATUS': ['ACTIVE', 'ACTIVE'],
            'OPEN_DATE': ['2024-01-15', '2024-01-16']
        })
        
        result_df = apply_source_qualifier(input_df)
        
        # Verify all columns present
        self.assertEqual(list(result_df.columns), list(input_df.columns))
        
        # Verify data unchanged
        pd.testing.assert_frame_equal(result_df, input_df)
    
    def test_missing_column_raises_error(self):
        """Verify error raised if expected column missing."""
        input_df = pd.DataFrame({
            'CUSTOMER_ID': ['C001'],
            'FIRST_NAME': ['John']
            # Missing other required columns
        })
        
        with self.assertRaises(ValueError) as context:
            apply_source_qualifier(input_df)
        
        self.assertIn('Missing expected columns', str(context.exception))


class TestExpressionTransformation(unittest.TestCase):
    """Test EXP_CUSTOMER_FEED transformation."""
    
    def test_adds_load_timestamp(self):
        """Verify LOAD_TS column is added with current timestamp."""
        input_df = pd.DataFrame({
            'CUSTOMER_ID': ['C001', 'C002'],
            'FIRST_NAME': ['John', 'Jane'],
            'LAST_NAME': ['Doe', 'Smith'],
            'EMAIL': ['john@example.com', 'jane@example.com'],
            'PHONE': ['555-0100', '555-0101'],
            'CUSTOMER_TYPE': ['RETAIL', 'COMMERCIAL'],
            'STATUS': ['ACTIVE', 'ACTIVE'],
            'OPEN_DATE': ['2024-01-15', '2024-01-16']
        })
        
        before_time = datetime.utcnow()
        result_df = apply_expression_transformation(input_df)
        after_time = datetime.utcnow()
        
        # Verify LOAD_TS column added
        self.assertIn('LOAD_TS', result_df.columns)
        
        # Verify all rows have same timestamp
        unique_timestamps = result_df['LOAD_TS'].unique()
        self.assertEqual(len(unique_timestamps), 1)
        
        # Verify timestamp is within test execution window
        load_ts = result_df['LOAD_TS'].iloc[0]
        self.assertGreaterEqual(load_ts, before_time)
        self.assertLessEqual(load_ts, after_time)
    
    def test_preserves_source_columns(self):
        """Verify all source columns remain unchanged."""
        input_df = pd.DataFrame({
            'CUSTOMER_ID': ['C001'],
            'FIRST_NAME': ['John'],
            'LAST_NAME': ['Doe'],
            'EMAIL': ['john@example.com'],
            'PHONE': ['555-0100'],
            'CUSTOMER_TYPE': ['RETAIL'],
            'STATUS': ['ACTIVE'],
            'OPEN_DATE': ['2024-01-15']
        })
        
        result_df = apply_expression_transformation(input_df)
        
        # Verify source columns unchanged (excluding LOAD_TS)
        for col in input_df.columns:
            pd.testing.assert_series_equal(
                result_df[col],
                input_df[col],
                check_names=True
            )


class TestStructuredLogger(unittest.TestCase):
    """Test structured logging with sanitization."""
    
    def test_sanitizes_newlines(self):
        """Verify newlines are escaped in log output."""
        logger = StructuredLogger('test')
        
        # Mock the actual logger
        with patch.object(logger.logger, 'info') as mock_info:
            logger.info('Test message', field='value\nwith\nnewlines')
            
            # Get the logged JSON
            logged_json = mock_info.call_args[0][0]
            
            # Verify newlines escaped
            self.assertNotIn('\n', logged_json)
            self.assertIn('\\n', logged_json)
    
    def test_redacts_sensitive_fields(self):
        """Verify sensitive fields are redacted."""
        logger = StructuredLogger('test')
        
        with patch.object(logger.logger, 'info') as mock_info:
            logger.info(
                'Test message',
                password='secret123',
                normal_field='visible'
            )
            
            logged_json = mock_info.call_args[0][0]
            
            # Verify password redacted
            self.assertIn('***REDACTED***', logged_json)
            self.assertNotIn('secret123', logged_json)
            
            # Verify normal field visible
            self.assertIn('visible', logged_json)


class TestConfigValidation(unittest.TestCase):
    """Test configuration loading and validation."""
    
    @patch.dict(os.environ, {}, clear=True)
    def test_missing_oracle_credentials_raises_error(self):
        """Verify error raised if Oracle credentials missing."""
        from customer_feed_loader import get_oracle_connection
        
        with self.assertRaises(ValueError) as context:
            with get_oracle_connection():
                pass
        
        self.assertIn('Missing required Oracle connection', str(context.exception))


if __name__ == '__main__':
    unittest.main()