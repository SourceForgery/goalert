package gcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/target/goalert/alert"
	"github.com/target/goalert/integrationkey"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/util/errutil"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation/validate"
)

/* Example payload
Documentation: https://cloud.google.com/monitoring/support/notification-options#webhooks
```
{
  "incident": {
    "incident_id": "0.opqiw61fsv7p",
    "scoping_project_id": "internal-project",
    "scoping_project_number": 12345,
    "url": "https://console.cloud.google.com/monitoring/alerting/incidents/0.lxfiw61fsv7p?project=internal-project",
    "severity": "no severity",
    "started_at": 1577840461,
    "ended_at": 1577877071,
    "state": "closed",
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
```
*/

type postBody struct {
	Version  string          `json:"version"`
	Incident IncidentDetails `json:"incident"`
}

type IncidentDetails struct {
	IncidentID              string            `json:"incident_id"`
	ScopingProjectID        string            `json:"scoping_project_id"`
	ScopingProjectNumber    int               `json:"scoping_project_number"`
	URL                     string            `json:"url"`
	StartedAt               int               `json:"started_at"`
	EndedAt                 int               `json:"ended_at"`
	State                   string            `json:"state"`
	Summary                 string            `json:"summary"`
	ApigeeURL               string            `json:"apigee_url"`
	ObservedValue           string            `json:"observed_value"`
	Resource                Resource          `json:"resource"`
	ResourceTypeDisplayName string            `json:"resource_type_display_name"`
	ResourceID              string            `json:"resource_id"`
	ResourceDisplayName     string            `json:"resource_display_name"`
	ResourceName            string            `json:"resource_name"`
	Metric                  Metric            `json:"metric"`
	Metadata                Metadata          `json:"metadata"`
	PolicyName              string            `json:"policy_name"`
	PolicyUserLabels        map[string]string `json:"policy_user_labels"`
	Documentation           Documentation     `json:"documentation"`
	Condition               Condition         `json:"condition"`
	ConditionName           string            `json:"condition_name"`
	ThresholdValue          string            `json:"threshold_value"`
}

type Documentation struct {
	Content  string              `json:"content"`
	MimeType string              `json:"mime_type"`
	Subject  string              `json:"subject"`
	Links    []DocumentationLink `json:"links"`
}

type DocumentationLink struct {
	DisplayName string `json:"displayName"`
	URL         string `json:"url"`
}

type Resource struct {
	Type   string            `json:"type"`
	Labels map[string]string `json:"labels"`
}

type Metric struct {
	Type        string            `json:"type"`
	DisplayName string            `json:"displayName"`
	Labels      map[string]string `json:"labels"`
}

type Metadata struct {
	SystemLabels map[string]string `json:"system_labels"`
	UserLabels   map[string]string `json:"user_labels"`
}

type Condition struct {
	Name               string             `json:"name"`
	DisplayName        string             `json:"displayName"`
	ConditionThreshold ConditionThreshold `json:"conditionThreshold"`
}

type ConditionThreshold struct {
	Filter         string  `json:"filter"`
	Comparison     string  `json:"comparison"`
	ThresholdValue float64 `json:"thresholdValue"`
	Duration       string  `json:"duration"`
	Trigger        Trigger `json:"trigger"`
}

type Trigger struct {
	Count int `json:"count"`
}

func (b postBody) Summary() string {
	return b.Incident.Metric.DisplayName + " " + b.Incident.ResourceDisplayName
}

func (b postBody) Details(payload string) string {
	var s strings.Builder
	if b.Incident.URL != "" {
		fmt.Fprintf(&s, "[GCP Alert UI](%s)\n\n", b.Incident.URL)
	}
	if b.Incident.Documentation != "" {
		s.WriteString(b.Incident.Documentation + "\n\n")
	}
	if payload != "" {
		fmt.Fprintf(&s, "## Payload\n\n```json\n%s\n```\n", payload)
	}
	return s.String()
}

func clientError(w http.ResponseWriter, code int, err error) bool {
	if err == nil {
		return false
	}

	http.Error(w, http.StatusText(code), code)
	return true
}

func GcpAlertMonitoringEventsAPI(aDB *alert.Store, intDB *integrationkey.Store) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		ctx := r.Context()

		err := permission.LimitCheckAny(ctx, permission.Service)
		if errutil.HTTPError(ctx, w, err) {
			return
		}
		serviceID := permission.ServiceID(ctx)

		var body postBody
		var buf bytes.Buffer
		err = json.NewDecoder(io.TeeReader(r.Body, &buf)).Decode(&body)
		if clientError(w, http.StatusBadRequest, err) {
			log.Logf(ctx, "bad request from GCP alertmanager: %v", err)
			return
		}

		var status alert.Status
		switch strings.ToLower(body.Incident.State) {
		case "open":
			status = alert.StatusTriggered
		case "closed":
			status = alert.StatusClosed
		default:
			log.Logf(ctx, "bad request from GCP alertmanager: missing or invalid state")
			log.Logf(ctx, "%s", r.Body)
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}

		data := make([]byte, buf.Len())
		copy(data, buf.Bytes())
		buf.Reset()
		err = json.Indent(&buf, data, "", "  ")
		if err == nil {
			data = buf.Bytes()
		}

		summary := validate.SanitizeText(body.Summary(), alert.MaxSummaryLength)
		msg := &alert.Alert{
			Summary:   summary,
			Details:   validate.SanitizeText(body.Details(string(data)), alert.MaxDetailsLength),
			Status:    status,
			Source:    alert.SourceGcp,
			ServiceID: serviceID,
			Dedup:     alert.NewUserDedup(body.Incident.IncidentID),
		}

		err = retry.DoTemporaryError(func(int) error {
			_, _, err = aDB.CreateOrUpdate(ctx, msg)
			return err
		},
			retry.Log(ctx),
			retry.Limit(10),
			retry.FibBackoff(time.Second),
		)
		if errutil.HTTPError(ctx, w, errors.Wrap(err, "create or update alert for GCP Alerting Monitor")) {
			return
		}
	}
}
