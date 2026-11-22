package policy

import (
	"testing"

	"github.com/sadbox/dep-review/internal/model"
)

func TestRouteFor(t *testing.T) {
	tests := []struct {
		u    model.Update
		want model.Route
	}{
		{model.Update{Name: "github.com/quic-go/quic-go", From: "0.63.0", To: "0.65.0", Type: model.Minor}, model.RouteReview},
		{model.Update{Name: "golang.org/x/net", From: "0.61.0", To: "0.63.0", Type: model.Minor}, model.RouteReview},
		{model.Update{Name: "left-pad", From: "0.1.0", To: "0.1.1", Type: model.Patch}, model.RouteReview},
		{model.Update{Name: "x", From: "1.2.0", To: "1.3.0", Type: model.Minor}, model.RouteReview},
		{model.Update{Name: "x", From: "1.2.0", To: "2.0.0", Type: model.Major}, model.RouteHuman},
		{model.Update{Name: "x", From: "0.9.0", To: "1.0.0", Type: model.Major}, model.RouteHuman},
		{model.Update{Name: "x", Type: model.Unknown}, model.RouteHuman},
		{model.Update{Name: "x", Type: model.Digest}, model.RouteReview},
		{model.Update{Name: "x", Type: model.Minor, NoOp: true}, model.RouteAuto},
	}
	for _, tt := range tests {
		if got := RouteFor(tt.u); got != tt.want {
			t.Errorf("%s %s->%s (%s): %s, want %s", tt.u.Name, tt.u.From, tt.u.To, tt.u.Type, got, tt.want)
		}
	}
}
