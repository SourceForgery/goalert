package gke

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
	Documentation           string            `json:"documentation"`
	Condition               Condition         `json:"condition"`
	ConditionName           string            `json:"condition_name"`
	ThresholdValue          string            `json:"threshold_value"`
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
		fmt.Fprintf(&s, "[GKE Alert UI](%s)\n\n", b.Incident.URL)
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

func GKEAlertMonitoringEventsAPI(aDB *alert.Store, intDB *integrationkey.Store) http.HandlerFunc {

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
			log.Logf(ctx, "bad request from prometheus alertmanager: %v", err)
			return
		}

		var status alert.Status
		switch strings.ToLower(body.Incident.State) {
		case "open":
			status = alert.StatusTriggered
		case "closed":
			status = alert.StatusClosed
		default:
			log.Logf(ctx, "bad request from prometheus alertmanager: missing or invalid state")
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
			Source:    alert.SourceGke,
			ServiceID: serviceID,
			Dedup:     alert.NewUserDedup(summary),
		}

		err = retry.DoTemporaryError(func(int) error {
			_, _, err = aDB.CreateOrUpdate(ctx, msg)
			return err
		},
			retry.Log(ctx),
			retry.Limit(10),
			retry.FibBackoff(time.Second),
		)
		if errutil.HTTPError(ctx, w, errors.Wrap(err, "create or update alert for GKE Alerting Monitor")) {
			return
		}
	}
}
