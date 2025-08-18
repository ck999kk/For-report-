#!/usr/bin/env python3
"""
Database Initialization Script
Professional Phone Intelligence System
"""

import sqlite3
import os
import sys
import logging
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_database_schema(db_path):
    """Create the complete database schema"""
    logger.info(f"Creating database schema at: {db_path}")
    
    # Ensure directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Evidence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                phone_number TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                data TEXT NOT NULL,
                hash_value TEXT NOT NULL,
                chain_of_custody TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                investigator TEXT NOT NULL,
                integrity_verified BOOLEAN DEFAULT TRUE,
                encryption_status TEXT DEFAULT 'encrypted',
                file_path TEXT,
                file_size INTEGER,
                metadata TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Chain of custody table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chain_of_custody (
                id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                action TEXT NOT NULL,
                investigator TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                session_id TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (evidence_id) REFERENCES evidence (id)
            )
        ''')
        
        # Investigations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                phone_number TEXT NOT NULL,
                investigator TEXT NOT NULL,
                investigation_type TEXT DEFAULT 'comprehensive',
                status TEXT DEFAULT 'pending',
                progress REAL DEFAULT 0.0,
                started_at DATETIME NOT NULL,
                completed_at DATETIME,
                error_message TEXT,
                results TEXT,
                report_path TEXT,
                session_id TEXT,
                priority INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Investigation results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS investigation_results (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                result_type TEXT NOT NULL,
                source TEXT NOT NULL,
                data TEXT NOT NULL,
                confidence_score REAL,
                timestamp DATETIME NOT NULL,
                metadata TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (investigation_id) REFERENCES investigations (id)
            )
        ''')
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                investigator TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                session_data TEXT
            )
        ''')
        
        # System logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                module TEXT,
                function TEXT,
                line_number INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                session_id TEXT,
                investigator TEXT,
                metadata TEXT
            )
        ''')
        
        # API usage table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint TEXT NOT NULL,
                method TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                status_code INTEGER,
                response_time REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                session_id TEXT,
                investigator TEXT,
                request_size INTEGER,
                response_size INTEGER
            )
        ''')
        
        # System status table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                component TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT
            )
        ''')
        
        # Create indexes for better performance
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON evidence(investigation_id)',
            'CREATE INDEX IF NOT EXISTS idx_evidence_phone ON evidence(phone_number)',
            'CREATE INDEX IF NOT EXISTS idx_evidence_timestamp ON evidence(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_custody_evidence ON chain_of_custody(evidence_id)',
            'CREATE INDEX IF NOT EXISTS idx_custody_timestamp ON chain_of_custody(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_investigations_phone ON investigations(phone_number)',
            'CREATE INDEX IF NOT EXISTS idx_investigations_investigator ON investigations(investigator)',
            'CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status)',
            'CREATE INDEX IF NOT EXISTS idx_investigations_started ON investigations(started_at)',
            'CREATE INDEX IF NOT EXISTS idx_results_investigation ON investigation_results(investigation_id)',
            'CREATE INDEX IF NOT EXISTS idx_results_type ON investigation_results(result_type)',
            'CREATE INDEX IF NOT EXISTS idx_sessions_investigator ON sessions(investigator)',
            'CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active)',
            'CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON system_logs(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_logs_level ON system_logs(level)',
            'CREATE INDEX IF NOT EXISTS idx_api_endpoint ON api_usage(endpoint)',
            'CREATE INDEX IF NOT EXISTS idx_api_timestamp ON api_usage(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_status_component ON system_status(component)',
            'CREATE INDEX IF NOT EXISTS idx_status_timestamp ON system_status(timestamp)'
        ]
        
        for index_sql in indexes:
            cursor.execute(index_sql)
        
        # Create triggers for updating timestamps
        triggers = [
            '''
            CREATE TRIGGER IF NOT EXISTS update_evidence_timestamp 
            AFTER UPDATE ON evidence 
            BEGIN 
                UPDATE evidence SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END
            ''',
            '''
            CREATE TRIGGER IF NOT EXISTS update_investigations_timestamp 
            AFTER UPDATE ON investigations 
            BEGIN 
                UPDATE investigations SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END
            '''
        ]
        
        for trigger_sql in triggers:
            cursor.execute(trigger_sql)
        
        # Insert initial system status
        cursor.execute('''
            INSERT OR IGNORE INTO system_status (component, status, message) 
            VALUES (?, ?, ?)
        ''', ('database', 'initialized', 'Database schema created successfully'))
        
        conn.commit()
        logger.info("Database schema created successfully")
        
        # Verify tables were created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        logger.info(f"Created tables: {', '.join(tables)}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error creating database schema: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def verify_database_integrity(db_path):
    """Verify database integrity and structure"""
    logger.info("Verifying database integrity...")
    
    if not os.path.exists(db_path):
        logger.error(f"Database file does not exist: {db_path}")
        return False
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check PRAGMA integrity_check
        cursor.execute("PRAGMA integrity_check")
        integrity_result = cursor.fetchone()
        
        if integrity_result[0] != 'ok':
            logger.error(f"Database integrity check failed: {integrity_result[0]}")
            return False
        
        # Check that all required tables exist
        required_tables = [
            'evidence', 'chain_of_custody', 'investigations', 
            'investigation_results', 'sessions', 'system_logs', 
            'api_usage', 'system_status'
        ]
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row[0] for row in cursor.fetchall()]
        
        missing_tables = set(required_tables) - set(existing_tables)
        if missing_tables:
            logger.error(f"Missing required tables: {', '.join(missing_tables)}")
            return False
        
        # Check table schemas
        for table in required_tables:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            if not columns:
                logger.error(f"Table {table} has no columns")
                return False
        
        logger.info("Database integrity verification passed")
        return True
        
    except Exception as e:
        logger.error(f"Error verifying database integrity: {e}")
        return False
    finally:
        conn.close()

def create_test_data(db_path):
    """Create test data for development"""
    logger.info("Creating test data...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Create test session
        test_session_id = "test-session-12345"
        cursor.execute('''
            INSERT OR REPLACE INTO sessions 
            (id, investigator, ip_address, user_agent, session_data) 
            VALUES (?, ?, ?, ?, ?)
        ''', (
            test_session_id,
            "Test Investigator",
            "127.0.0.1",
            "Test User Agent",
            '{"test": true}'
        ))
        
        # Create test investigation
        test_investigation_id = "test-investigation-67890"
        cursor.execute('''
            INSERT OR REPLACE INTO investigations 
            (id, phone_number, investigator, investigation_type, status, progress, started_at, session_id) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            test_investigation_id,
            "+1234567890",
            "Test Investigator",
            "comprehensive",
            "completed",
            100.0,
            datetime.now(),
            test_session_id
        ))
        
        # Create test evidence
        cursor.execute('''
            INSERT OR REPLACE INTO evidence 
            (id, investigation_id, phone_number, evidence_type, data, hash_value, 
             chain_of_custody, timestamp, investigator) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            "test-evidence-001",
            test_investigation_id,
            "+1234567890",
            "validation",
            '{"test": "data"}',
            "test-hash-123",
            '{"created": "' + datetime.now().isoformat() + '"}',
            datetime.now(),
            "Test Investigator"
        ))
        
        # Create system status entries
        cursor.execute('''
            INSERT OR REPLACE INTO system_status 
            (component, status, message) 
            VALUES (?, ?, ?)
        ''', ('web_server', 'operational', 'Web server is running'))
        
        cursor.execute('''
            INSERT OR REPLACE INTO system_status 
            (component, status, message) 
            VALUES (?, ?, ?)
        ''', ('phone_intelligence', 'operational', 'Phone intelligence system is ready'))
        
        conn.commit()
        logger.info("Test data created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error creating test data: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def backup_database(db_path, backup_dir="backups"):
    """Create a backup of the database"""
    if not os.path.exists(db_path):
        logger.warning(f"Database file does not exist: {db_path}")
        return False
    
    # Create backup directory
    backup_path = Path(backup_dir)
    backup_path.mkdir(exist_ok=True)
    
    # Create backup filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"phone_evidence_backup_{timestamp}.db"
    backup_file = backup_path / backup_filename
    
    try:
        # Use SQLite backup API
        source_conn = sqlite3.connect(db_path)
        backup_conn = sqlite3.connect(str(backup_file))
        
        source_conn.backup(backup_conn)
        
        source_conn.close()
        backup_conn.close()
        
        logger.info(f"Database backed up to: {backup_file}")
        return str(backup_file)
        
    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        return False

def main():
    """Main function to initialize database"""
    db_path = "phone_evidence.db"
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Initialize Phone Intelligence Database")
    parser.add_argument("--db-path", default=db_path, help="Database file path")
    parser.add_argument("--create-test-data", action="store_true", help="Create test data")
    parser.add_argument("--verify-only", action="store_true", help="Only verify database")
    parser.add_argument("--backup", action="store_true", help="Create backup before changes")
    parser.add_argument("--force", action="store_true", help="Force recreation of database")
    
    args = parser.parse_args()
    
    logger.info("Professional Phone Intelligence System - Database Initialization")
    logger.info(f"Database path: {args.db_path}")
    
    # Create backup if requested
    if args.backup and os.path.exists(args.db_path):
        backup_file = backup_database(args.db_path)
        if backup_file:
            logger.info(f"Backup created: {backup_file}")
    
    # If force flag is set, remove existing database
    if args.force and os.path.exists(args.db_path):
        os.remove(args.db_path)
        logger.info("Existing database removed")
    
    # Verify only mode
    if args.verify_only:
        if verify_database_integrity(args.db_path):
            logger.info("Database verification successful")
            return 0
        else:
            logger.error("Database verification failed")
            return 1
    
    # Create database schema
    if not create_database_schema(args.db_path):
        logger.error("Failed to create database schema")
        return 1
    
    # Verify database integrity
    if not verify_database_integrity(args.db_path):
        logger.error("Database integrity verification failed")
        return 1
    
    # Create test data if requested
    if args.create_test_data:
        if not create_test_data(args.db_path):
            logger.error("Failed to create test data")
            return 1
    
    logger.info("Database initialization completed successfully")
    return 0

if __name__ == "__main__":
    sys.exit(main())