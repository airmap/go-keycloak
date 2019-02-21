// Copyright 2019 AirMap Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keycloak

import (
	"time"
)

// ParseTime converts a Keycloak time (represented as milliseconds since the
// epoch) into a time.Time.
func ParseTime(msec int64) time.Time {
	sec := msec / 1000
	nsec := (msec % 1000) * 1000000
	return time.Unix(sec, nsec)
}

// FormatTime converts a time.Time into a Keycloak time.
func FormatTime(t time.Time) int64 {
	return t.UnixNano() / 1000000
}
