package smoke

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

func TestGCPAlertManager(t *testing.T) {
	t.Parallel()

	const sql = `
	insert into users (id, name, email)
	values
		({{uuid "user"}}, 'bob', 'joe');

	insert into user_contact_methods (id, user_id, name, type, value)
	values
		({{uuid "cm1"}}, {{uuid "user"}}, 'personal', 'SMS', {{phone "1"}});

	insert into user_notification_rules (user_id, contact_method_id, delay_minutes)
	values
		({{uuid "user"}}, {{uuid "cm1"}}, 0);

	insert into escalation_policies (id, name)
	values
		({{uuid "eid"}}, 'esc policy');

	insert into escalation_policy_steps (id, escalation_policy_id)
	values
		({{uuid "esid"}}, {{uuid "eid"}});

	insert into escalation_policy_actions (escalation_policy_step_id, user_id)
	values
		({{uuid "esid"}}, {{uuid "user"}});

	insert into services (id, escalation_policy_id, name)
	values
		({{uuid "sid"}}, {{uuid "eid"}}, 'service');

	insert into integration_keys (id, type, name, service_id)
	values
		({{uuid "int_key"}}, 'gcpAlertingMonitoring', 'my key', {{uuid "sid"}});
`
	h := harness.NewHarness(t, sql, "gcp-alertmanager-integration")
	defer h.Close()

	url := h.URL() + "/api/v2/gcp/incoming?token=" + h.UUID("int_key")

	resp, err := http.Post(url, "application/json", bytes.NewBufferString(`
		{
		  "version": "test",
		  "incident": {
			"incident_id": "12345",
			"scoping_project_id": "12345",
			"scoping_project_number": 12345,
			"url": "http://www.example.com",
			"started_at": 0,
			"ended_at": 0,
			"state": "OPEN",
			"summary": "Test Incident",
			"apigee_url": "http://www.example.com",
			"observed_value": "1.0",
			"resource": {
			  "type": "example_resource",
			  "labels": {
				"example": "label"
			  }
			},
			"resource_type_display_name": "Example Resource Type",
			"resource_id": "12345",
			"resource_display_name": "Example Resource",
			"resource_name": "projects/12345/example_resources/12345",
			"metric": {
			  "type": "test.googleapis.com/metric",
			  "displayName": "Test Metric",
			  "labels": {
				"example": "label"
			  }
			},
			"metadata": {
			  "system_labels": {
				"example": "label"
			  },
			  "user_labels": {
				"example": "label"
			  }
			},
			"policy_name": "projects/12345/alertPolicies/12345",
			"policy_user_labels": {
			  "example": "label"
			},
			"documentation": "Test documentation",
			"condition": {
			  "name": "projects/12345/alertPolicies/12345/conditions/12345",
			  "displayName": "Example condition",
			  "conditionThreshold": {
				"filter": "metric.type=\"test.googleapis.com/metric\" resource.type=\"example_resource\"",
				"comparison": "COMPARISON_GT",
				"thresholdValue": 0.5,
				"duration": "0s",
				"trigger": {
				  "count": 1
				}
			  }
			},
			"condition_name": "Example condition",
			"threshold_value": "0.5"
		  }
		}
		`))
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode, "HTTP response code")

	h.Twilio(t).Device(h.Phone("1")).ExpectSMS("Test Metric Example Resource")
}
