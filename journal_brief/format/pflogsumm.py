"""
Copyright (c) 2015 Tim Waugh <tim@cyberelk.net>

## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.

## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
"""

from journal_brief.format import EntryFormatter
import locale
import subprocess


class PflogsummFormatter(EntryFormatter):
    """
    Show a summary of login sessions
    """

    FORMAT_NAME = "pflogsumm"
    FILTER_INCLUSIONS = [
        {
            '_SYSTEMD_UNIT': ['postfix.service'],
        },
    ]

    def __init__(self, *args, **kwargs):
        super(PflogsummFormatter, self).__init__(*args, **kwargs)
        self.logs = []

    def format(self, entry):
        self.logs.append(self._format(entry))
        return ''

    FORMAT = '{__REALTIME_TIMESTAMP} {_HOSTNAME} {SYSLOG_IDENTIFIER}: {MESSAGE}\n'
    TIMESTAMP_FORMAT = '%b %d %T'

    def format_timestamp(self, entry, field):
        """
        Convert entry field from datetime.datetime instance to string

        Uses strftime() and TIMESTAMP_FORMAT
        """

        if field in entry:
            dt = entry[field]
            (old_code, old_enc) = locale.getlocale(locale.LC_TIME)
            locale.setlocale(locale.LC_TIME, '')
            entry[field] = dt.strftime(self.TIMESTAMP_FORMAT)
            locale.setlocale(locale.LC_TIME, (old_code + '.' + old_enc) if old_code else '')

    def _format(self, entry):
        """
        Format a journal entry using FORMAT

        :param entry: dict, journal entry
        :return: str, formatted string
        """

        self.format_timestamp(entry, '__REALTIME_TIMESTAMP')

        if '_HOSTNAME' not in entry:
            entry['_HOSTNAME'] = 'localhost'

        if 'SYSLOG_IDENTIFIER' not in entry:
            entry['SYSLOG_IDENTIFIER'] = entry.get('_COMM', '?')

        if '_PID' in entry:
            entry['SYSLOG_IDENTIFIER'] += '[{0}]'.format(entry['_PID'])
        elif 'SYSLOG_PID' in entry:
            entry['SYSLOG_IDENTIFIER'] += '[{0}]'.format(entry['SYSLOG_PID'])

        return self.FORMAT.format(**entry)

    def flush(self):
        result = subprocess.run(['pflogsumm', '--problems-first'], input=''.join(self.logs), text=True, capture_output=True)

        return result.stderr + result.stdout
