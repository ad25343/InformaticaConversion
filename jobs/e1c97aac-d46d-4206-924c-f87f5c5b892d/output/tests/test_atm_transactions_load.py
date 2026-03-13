"""
Unit tests for m_fct_atm_transactions_load

Tests each transformation function independently with sample data.
"""

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime
import pandas as pd
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from extract_atm_transactions import (
    apply_expression_transformations,
    load_config
)


class TestExpressionTransformations(unittest.TestCase):
    """Test suite for EXP_ATM_TRANSACTIONS transformation"""
    
    def setUp(self):
        """Create sample input data for testing"""
        self.sample_data = pd.DataFrame({
            'TXN_ID': [1, 2, 3, 4, 5],
            'TXN_DATE': pd.to_datetime(['2024-01-01', '2024-01-02', '2024-01-03', '2024-01-04', '2024-01-05']),
            'ACCOUNT_ID': [1001, 1002, 1003, 1004, 1005],
            'ATM_ID': ['ATM001', 'ATM002', 'ATM003', 'ATM004', 'ATM005'],
            'TXN_TYPE': ['WITHDRAWAL', 'DEPOSIT', 'WITHDRAWAL', 'BALANCE', 'WITHDRAWAL'],
            'AMOUNT': [100.00, 250.00, 75.50, 0.00, 200.00],
            'STATUS': ['COMPLETE', 'COMPLETE', 'COMPLETE', 'COMPLETE', 'FAILED'],
            'FEE_AMOUNT': [2.50, 0.00, 2.50, 0.00, 2.50],
            'CARD_LAST4': ['1234', '5678', '9012', '3456', '7890']
        })
    
    def test_expression_pass_through(self):
        """Test that expression transformation passes data through unchanged"""
        result = apply_expression_transformations(self.sample_data)
        
        # Verify all rows are preserved
        self.assertEqual(len(result), len(self.sample_data))
        
        # Verify all columns are preserved
        self.assertEqual(list(result.columns), list(self.sample_data.columns))
        
        # Verify data values are unchanged
        pd.testing.assert_frame_equal(result, self.sample_data)
    
    def test_expression_with_nulls(self):
        """Test expression transformation handles NULL values correctly"""
        data_with_nulls = self.sample_data.copy()
        data_with_nulls.loc[0, 'TXN_ID'] = None
        data_with_nulls.loc[2, 'AMOUNT'] = None
        
        result = apply_expression_transformations(data_with_nulls)
        
        # Verify NULL values are preserved
        self.assertTrue(pd.isna(result.loc[0, 'TXN_ID']))
        self.assertTrue(pd.isna(result.loc[2, 'AMOUNT']))
    
    def test_expression_empty_dataframe(self):
        """Test expression transformation handles empty DataFrame"""
        empty_df = pd.DataFrame()
        result = apply_expression_transformations(empty_df)
        
        self.assertTrue(result.empty)


class TestConfigLoading(unittest.TestCase):
    """Test suite for configuration loading"""
    
    @patch('builtins.open', create=True)
    @patch('yaml.safe_load')
    def test_config_load(self, mock_yaml_load, mock_open):
        """Test configuration loading from YAML file"""
        mock_config = {
            'source': {
                'database_type': 'oracle',
                'schema': 'OLTP',
                'table': 'ATM_TRANSACTIONS'
            },
            'target': {
                'database_type': 'oracle',
                'schema': 'DWH',
                'table': 'FCT_ATM_TRANSACTIONS'
            }
        }
        mock_yaml_load.return_value = mock_config
        
        config = load_config('test_config.yaml')
        
        self.assertEqual(config['source']['schema'], 'OLTP')
        self.assertEqual(config['target']['table'], 'FCT_ATM_TRANSACTIONS')


if __name__ == '__main__':
    unittest.main()