package suppressionforwarding

import "time"

func SetUpstreamClock(u *Upstream, now func() time.Time) {
	u.now = now
}
