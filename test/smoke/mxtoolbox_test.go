package smoke

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

func TestMxToolBox(t *testing.T) {
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
		({{uuid "int_key"}}, 'mxToolBox', 'my key', {{uuid "sid"}});
`
	h := harness.NewHarness(t, sql, "mxtoolbox-integration")
	defer h.Close()

	url := h.URL() + "/api/v2/mxtoolbox/incoming?token=" + h.UUID("int_key")

	resp, err := http.Post(url, "application/json", bytes.NewBufferString(`
		{
			  "Command": "DNS",
			  "Argument": "example.com",
			  "Name": "My DNS Monitor",
			  "TransitionId": 1234,
			  "AlertType": "DOWN",
			  "AlertTime": "Wed, 27 Nov 2024 11:17:09 GMT",
			  "PolicyName": "DNS Monitor",
			  "StatusChange": "Some information about the current status",
			  "UrlDetails": "https://mxtoolbox.com"
		}`))
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode, "HTTP response code")

	h.Twilio(t).Device(h.Phone("1")).ExpectSMS("My DNS Monitor DOWN (DNS Monitor)")
}
