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
		  "incident": {
			"incident_id": "0.opqiw61fsv7p",
			"scoping_project_id": "internal-project",
			"scoping_project_number": 12345,
			"url": "https://console.cloud.google.com/monitoring/alerting/incidents/0.lxfiw61fsv7p?project=internal-project",
			"severity": "no severity",
			"started_at": 1577840461,
			"ended_at": 1577877071,
			"state": "open",
			"resource_id": "11223344",
			"resource_name": "internal-project gke-cluster-1-default-pool-e2df4cbd-dgp3",
			"resource_display_name": "gke-cluster-1-default-pool-e2df4cbd-dgp3",
			"resource_type_display_name": "VM Instance",
			"resource": {
			  "type": "gce_instance",
			  "labels": {
				"instance_id": "11223344",
				"project_id": "internal-project",
				"zone": "us-central1-c"
			  }
			},
			"metric": {
			  "type": "compute.googleapis.com/instance/cpu/utilization",
			  "displayName": "CPU utilization",
			  "labels": {
				"instance_name": "the name of the VM instance"
			  }
			},
			"metadata": {
			  "system_labels": { "labelkey": "labelvalue" },
			  "user_labels": { "labelkey": "labelvalue" }
			},
			"policy_name": "Monitor-Project-Cluster",
			"policy_user_labels" : {
				"user-label-1" : "important label",
				"user-label-2" : "another label"
			},
			"condition_name": "VM Instance - CPU utilization [MAX]",
			"threshold_value": "0.9",
			"observed_value": "0.835",
			"condition": {
			  "name": "projects/internal-project/alertPolicies/1234567890123456789/conditions/1234567890123456789",
			  "displayName": "VM Instance - CPU utilization [MAX]",
			  "conditionThreshold": {
				"filter": "metric.type=\"compute.googleapis.com/instance/cpu/utilization\" resource.type=\"gce_instance\" metadata.system_labels.\"state\"=\"ACTIVE\"",
				"aggregations": [
				  {
					"alignmentPeriod": "120s",
					"perSeriesAligner": "ALIGN_MEAN"
				  }
				],
				"comparison": "COMPARISON_GT",
				"thresholdValue": 0.9,
				"duration": "0s",
				"trigger": {
				  "count": 1
				}
			  }
			},
			"documentation": {
			  "content": "TEST ALERT\n\npolicy.name=projects/internal-project/alertPolicies/1234567890123456789\n\npolicy.display_name=Monitored-Project-NO-GROUPBY\n\ncondition.name=projects/nternal-project/alertPolicies/1234567890123456789/conditions/1234567890123456789\n\ncondition.display_name=VM Instance - CPU utilization [MAX]\n\nproject=internal-project\n\nresrouce.project=internal-project \n\nDONE\n",
			  "mime_type": "text/markdown",
			  "subject": "ALERT - No severity",
			  "links": [
				{
				  "displayName": "Playbook",
				  "url": "https://myownpersonaldomain.com/playbook?name=${resource.name}"
				}
			  ]
			},
			"summary": "CPU utilization for internal-project gke-cluster-1-16-default-pool-e2df4cbd-dgp3 with metric labels {instance_name=gke-cluster-1-default-pool-e2df4cbd-dgp3} and system labels {state=ACTIVE} returned to normal with a value of 0.835."
		  },
		  "version": "1.2"
		}
		`))
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode, "HTTP response code")

	h.Twilio(t).Device(h.Phone("1")).ExpectSMS("CPU utilization for internal-project gke-cluster-1-16-d")
}
