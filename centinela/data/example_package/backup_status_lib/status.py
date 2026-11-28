"""Reading the backup job's status file: pure functions, so they are easy to test."""
import json
from collections import namedtuple

Report = namedtuple("Report", "ok finished message")


def parse(text):
    """'{"ok": true, "finished": 1767225600, "message": "..."}' -> Report. ValueError says what is wrong."""
    try:
        data = json.loads(text)
    except ValueError:
        raise ValueError("not JSON") from None
    if not isinstance(data, dict) or not isinstance(data.get("ok"), bool):
        raise ValueError('needs {"ok": true or false, "finished": <unix time>}')
    finished = data.get("finished")
    if not isinstance(finished, (int, float)) or isinstance(finished, bool):
        raise ValueError('"finished" must be a unix time')
    return Report(data["ok"], float(finished), str(data.get("message", ""))[:120])


def age_hours(report, now):
    return max(0.0, (now - report.finished) / 3600)
