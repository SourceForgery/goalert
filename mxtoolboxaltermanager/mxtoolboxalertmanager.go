package mxtoolbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
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
Documentation: https://mxtoolbox.com/monitoring/notifications
```
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
}
```
*/

type postBody struct {
	Command      string `json:"Command"`
	Argument     string `json:"Argument"`
	Name         string `json:"Name"`
	TransitionId int    `json:"TransitionId"`
	AlertType    string `json:"AlertType"`
	AlertTime    string `json:"AlertTime"`
	PolicyName   string `json:"PolicyName"`
	StatusChange string `json:"StatusChange"`
	UrlDetails   string `json:"UrlDetails"`
}

func (b postBody) Summary() string {
	return b.Name + " " + b.AlertType + " (" + b.PolicyName + ")"
}

func (b postBody) Details(payload string) string {
	var s strings.Builder
	if b.UrlDetails != "" {
		fmt.Fprintf(&s, "[MxToolbox](%s)\n\n", b.UrlDetails)
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

func MxToolBoxAlert(aDB *alert.Store, intDB *integrationkey.Store) http.HandlerFunc {

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
		switch strings.ToLower(body.AlertType) {
		case "down":
			status = alert.StatusTriggered
		case "up":
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
			Source:    alert.SourceMxToolbox,
			ServiceID: serviceID,
			Dedup:     alert.NewUserDedup(strconv.Itoa(body.TransitionId) + "MXTOOLBOX"),
		}

		err = retry.DoTemporaryError(func(int) error {
			_, _, err = aDB.CreateOrUpdate(ctx, msg)
			return err
		},
			retry.Log(ctx),
			retry.Limit(10),
			retry.FibBackoff(time.Second),
		)
		if errutil.HTTPError(ctx, w, errors.Wrap(err, "create or update alert for MxToolbox")) {
			return
		}
	}
}
