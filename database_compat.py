"""Small compatibility layer for using existing SQLite-style SQL with Psycopg."""

import re
import sqlite3

import psycopg


IDENTITY_COLUMNS = {
    "users": "id",
    "hardware": "item_id",
    "password_reset_requests": "request_id",
    "equipment_requests": "request_id",
    "maintenance_schedules": "maintenance_id"
}


def _raise_compatible_error(error):
    """Convert Psycopg errors to errors already handled by the desktop code."""

    if isinstance(error, psycopg.errors.UniqueViolation):
        raise sqlite3.IntegrityError(str(error)) from error

    if isinstance(error, psycopg.IntegrityError):
        raise sqlite3.IntegrityError(str(error)) from error

    raise sqlite3.DatabaseError(str(error)) from error


class PostgreSQLCursor:
    """Expose the cursor methods expected by the original SQLite controllers."""

    def __init__(self, cursor):
        self._cursor = cursor
        self._lastrowid = None

    @staticmethod
    def _translate_query(query):
        cleaned = query.strip()

        if cleaned.upper() == "BEGIN IMMEDIATE":
            return "BEGIN"

        # The existing application uses SQLite question-mark placeholders.
        return query.replace("?", "%s")

    def execute(self, query, parameters=None):
        translated = self._translate_query(query)
        values = () if parameters is None else parameters
        self._lastrowid = None

        try:
            insert_match = re.match(
                r"\s*INSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*)",
                translated,
                re.IGNORECASE,
            )

            if insert_match and "RETURNING" not in translated.upper():
                table_name = insert_match.group(1).lower()
                id_column = IDENTITY_COLUMNS.get(table_name)

                if id_column:
                    translated = (
                        f'{translated.rstrip().rstrip(";")} '
                        f'RETURNING "{id_column}"'
                    )

                    self._cursor.execute(translated, values)
                    returned = self._cursor.fetchone()
                    self._lastrowid = returned[0] if returned else None
                    return self

            self._cursor.execute(translated, values)
            return self

        except psycopg.Error as error:
            _raise_compatible_error(error)

    def executemany(self, query, parameter_rows):
        try:
            self._cursor.executemany(
                self._translate_query(query),
                parameter_rows,
            )
            return self
        except psycopg.Error as error:
            _raise_compatible_error(error)

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def description(self):
        return self._cursor.description

    @property
    def lastrowid(self):
        return self._lastrowid

    def close(self):
        self._cursor.close()


class PostgreSQLConnection:
    """Expose the connection methods expected by the original SQLite code."""

    def __init__(self, connection):
        self._connection = connection

    def cursor(self):
        return PostgreSQLCursor(self._connection.cursor())

    def execute(self, query, parameters=None):
        cursor = self.cursor()
        cursor.execute(query, parameters)
        return cursor

    def commit(self):
        try:
            self._connection.commit()
        except psycopg.Error as error:
            _raise_compatible_error(error)

    def rollback(self):
        try:
            self._connection.rollback()
        except psycopg.Error as error:
            _raise_compatible_error(error)

    def close(self):
        self._connection.close()


def connect_postgresql(database_url):
    """Create a PostgreSQL connection for the Flask and controller code."""

    try:
        connection = psycopg.connect(
            database_url,
            connect_timeout=30,
        )
        return PostgreSQLConnection(connection)
    except psycopg.Error as error:
        _raise_compatible_error(error)