# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""
Tests for sandboxed Jinja rendering and validation of RLS filter clauses.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from superset.connectors.sqla.models import (
    _render_rls_clause,
    _validate_rls_clause,
)
from superset.exceptions import SupersetSecurityException


def _make_processor(context: dict[str, object] | None = None) -> MagicMock:
    processor = MagicMock()
    processor.get_context.return_value = context or {}
    return processor


def test_render_rls_clause_allows_user_identity_context() -> None:
    processor = _make_processor({"current_username": lambda: "alice"})
    rendered = _render_rls_clause(
        "tenant = '{{ current_username() }}'",
        processor,
    )
    assert rendered == "tenant = 'alice'"


def test_render_rls_clause_strips_disallowed_context() -> None:
    """Context variables not on the RLS whitelist must not be exposed."""
    processor = _make_processor(
        {
            "current_username": lambda: "alice",
            # url_param is user-controlled in normal SQL templating and must
            # not be available to RLS filter clauses.
            "url_param": lambda name: "pwned",
        }
    )
    with pytest.raises(Exception):  # noqa: B017, PT011
        _render_rls_clause(
            "tenant = '{{ url_param(\"who\") }}'",
            processor,
        )


def test_render_rls_clause_blocks_attribute_escape() -> None:
    """The sandboxed environment must block attribute-based escapes."""
    processor = _make_processor({"current_username": lambda: "alice"})
    with pytest.raises(Exception):  # noqa: B017, PT011
        _render_rls_clause(
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            processor,
        )


@pytest.mark.parametrize(
    "clause",
    [
        "1=1; DROP TABLE users",
        "id = 1 -- comment",
        "id = 1 /* comment */",
        "id = 1 OR 1=1; DELETE FROM users",
        "id IN (SELECT id FROM users WHERE 1=1) AND 1=1 UNION INSERT INTO foo VALUES(1)",  # noqa: E501
    ],
)
def test_validate_rls_clause_rejects_dangerous_patterns(clause: str) -> None:
    with pytest.raises(SupersetSecurityException):
        _validate_rls_clause(clause)


@pytest.mark.parametrize(
    "clause",
    [
        "tenant_id = 5",
        "region = 'US'",
        "col1 = 'value1'",
        "active = true",
        "user_id = 123 AND org_id = 7",
    ],
)
def test_validate_rls_clause_accepts_typical_filters(clause: str) -> None:
    _validate_rls_clause(clause)


def test_render_rls_clause_rejects_template_producing_forbidden_sql() -> None:
    """Even if a template renders successfully, the resulting SQL must be
    validated — a sandboxed template whose output smuggles a second statement
    should still be rejected."""
    processor = _make_processor(
        {"current_username": lambda: "alice'; DROP TABLE users; --"}
    )
    with pytest.raises(SupersetSecurityException):
        _render_rls_clause(
            "tenant = '{{ current_username() }}'",
            processor,
        )
