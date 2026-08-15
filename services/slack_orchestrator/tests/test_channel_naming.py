"""Channel naming convention tests."""

from datetime import datetime

import pytest

from services.slack_orchestrator.utils.channel_naming import (
    ChannelNamingError,
    extract_incident_number,
    generate_channel_name,
    generate_collision_suffix,
)


def test_generate_channel_name_pads_number():
    year = datetime.now().year
    assert generate_channel_name("INC-42") == f"sec-ops-inc-{year}-042"


def test_generate_channel_name_large_number_not_truncated():
    year = datetime.now().year
    assert generate_channel_name("INC-999999") == f"sec-ops-inc-{year}-999999"


def test_generate_channel_name_rejects_bad_format():
    with pytest.raises(ChannelNamingError):
        generate_channel_name("not-an-incident")


def test_extract_incident_number():
    assert extract_incident_number("INCIDENT-123") == "123"


def test_collision_suffix_shape():
    suffix = generate_collision_suffix()
    # MMDD-HHMM
    assert len(suffix) == 9
    assert suffix[4] == "-"
