#!/usr/bin/env python3
"""
Personal data functions: Redact logs and connect to MySQL.
"""

import re
import logging
from typing import List
import mysql.connector
import os


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter for log messages."""
    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initialize RedactingFormatter."""
        self.fields = fields
        super(RedactingFormatter, self).__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        """Format log message with redacted sensitive fields."""
        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """Redact sensitive fields in log message."""
    for field in fields:
        message = re.sub(rf"{field}=.*?{separator}",
                         f"{field}={redaction}{separator}", message)
    return message


def get_logger() -> logging.Logger:
    """Create and return logger named 'user_data'."""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(stream_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Return MySQL database connection."""
    user_name = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    pword = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    dbase = os.getenv('PERSONAL_DATA_DB_NAME')

    db_connect = mysql.connector.connect(
        user=user_name,
        password=pword,
        host=host,
        database=dbase)
    return db_connect


def main():
    """Retrieve and print data from the database."""
    db_connection = get_db()
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM users")
    data = cursor.fetchall()
    for row in data:
        for column_value in row:
            print(column_value)

    cursor.close()
    db_connection.close()


if __name__ == '__main__':
    main()
