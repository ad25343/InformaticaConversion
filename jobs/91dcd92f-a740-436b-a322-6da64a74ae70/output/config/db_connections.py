"""
Database connection configuration for m_fct_atm_transactions_load.
All credentials sourced from environment variables.
"""

import os
from typing import Dict, Any


def get_source_connection_config() -> Dict[str, Any]:
    """
    Get source Oracle database connection configuration.
    All credentials must be provided via environment variables.
    
    Returns:
        Dict containing connection parameters
        
    Raises:
        ValueError: If required environment variables are missing
    """
    required_vars = [
        'SOURCE_ORACLE_HOST',
        'SOURCE_ORACLE_PORT',
        'SOURCE_ORACLE_SERVICE',
        'SOURCE_ORACLE_USER',
        'SOURCE_ORACLE_PASSWORD'
    ]
    
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    return {
        'host': os.environ.get('SOURCE_ORACLE_HOST'),
        'port': int(os.environ.get('SOURCE_ORACLE_PORT')),
        'service_name': os.environ.get('SOURCE_ORACLE_SERVICE'),
        'user': os.environ.get('SOURCE_ORACLE_USER'),
        'password': os.environ.get('SOURCE_ORACLE_PASSWORD'),
        'protocol': 'tcps',  # TLS-encrypted connection required
        'ssl_server_dn_match': True
    }


def get_target_connection_config() -> Dict[str, Any]:
    """
    Get target Oracle database connection configuration.
    All credentials must be provided via environment variables.
    
    Returns:
        Dict containing connection parameters
        
    Raises:
        ValueError: If required environment variables are missing
    """
    required_vars = [
        'TARGET_ORACLE_HOST',
        'TARGET_ORACLE_PORT',
        'TARGET_ORACLE_SERVICE',
        'TARGET_ORACLE_USER',
        'TARGET_ORACLE_PASSWORD'
    ]
    
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    return {
        'host': os.environ.get('TARGET_ORACLE_HOST'),
        'port': int(os.environ.get('TARGET_ORACLE_PORT')),
        'service_name': os.environ.get('TARGET_ORACLE_SERVICE'),
        'user': os.environ.get('TARGET_ORACLE_USER'),
        'password': os.environ.get('TARGET_ORACLE_PASSWORD'),
        'protocol': 'tcps',  # TLS-encrypted connection required
        'ssl_server_dn_match': True
    }