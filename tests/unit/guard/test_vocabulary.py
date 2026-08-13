"""Tests for the security metadata vocabulary helper."""

from __future__ import annotations

from arcjet.guard import security_metadata


class TestSecurityMetadata:
    """Tests for security_metadata() builder."""

    def test_empty_returns_empty_dict(self):
        """All-None fields return an empty dict."""
        result = security_metadata()
        assert result == {}

    def test_user_field(self):
        """user field maps to 'user' key."""
        result = security_metadata(user="u_1")
        assert result == {"user": "u_1"}

    def test_agent_field(self):
        """agent field maps to 'agent' key."""
        result = security_metadata(agent="gpt-4")
        assert result == {"agent": "gpt-4"}

    def test_workflow_field(self):
        """workflow field maps to 'workflow' key."""
        result = security_metadata(workflow="email_chain")
        assert result == {"workflow": "email_chain"}

    def test_data_class_field(self):
        """data_class field maps to 'data-class' key (kebab-case)."""
        result = security_metadata(data_class="pii")
        assert result == {"data-class": "pii"}

    def test_destination_field(self):
        """destination field maps to 'destination' key."""
        result = security_metadata(destination="sendgrid")
        assert result == {"destination": "sendgrid"}

    def test_reversibility_field(self):
        """reversibility field maps to 'reversibility' key."""
        result = security_metadata(reversibility="irreversible")
        assert result == {"reversibility": "irreversible"}

    def test_resource_field(self):
        """resource field maps to 'resource' key."""
        result = security_metadata(resource="invoice")
        assert result == {"resource": "invoice"}

    def test_multiple_fields(self):
        """Multiple fields are all included."""
        result = security_metadata(
            user="u_1",
            agent="gpt-4",
            data_class="pii",
        )
        assert result == {
            "user": "u_1",
            "agent": "gpt-4",
            "data-class": "pii",
        }

    def test_partial_fields(self):
        """Omitted fields are not in the result."""
        result = security_metadata(
            user="u_1",
            destination="sendgrid",
        )
        assert result == {
            "user": "u_1",
            "destination": "sendgrid",
        }
        assert "agent" not in result
        assert "workflow" not in result

    def test_none_fields_omitted(self):
        """Explicitly passing None omits that field."""
        result = security_metadata(
            user="u_1",
            agent=None,
            workflow="email",
        )
        assert result == {
            "user": "u_1",
            "workflow": "email",
        }
