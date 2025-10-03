/*
LIVEKIT-JWT-SERVICE-AMS High Performance Security Enhanched Livekit JWT Service
Copyright (c) 2025 Albert Blasczykowski (Aless Microsystems)

This program is licensed under the Aless Microsystems Source-Available License (Non-Commercial, No Military) v1.0 Available in the Root
Directory of the project as LICENSE in Text Format.
You may use, copy, modify, and distribute this program for Non-Commercial purposes only, subject to the terms of that license.
Use by or for military, intelligence, or defense entities or purposes is strictly prohibited.

If you distribute this program in object form or make it available to others over a network, you must provide the complete
corresponding source code for the provided functionality under this same license.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the License for details.

You should have received a copy of the License along with this program; if not, see the LICENSE file included with this source.
*/

package main

import (
	"html"
	"os"
	"strconv"
	"strings"
)

func Dequote(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			s = s[1 : len(s)-1]
			continue
		}
		break
	}
	return s
}

func getEnv(key string) string {
	v, ok := os.LookupEnv(key)
	if !ok {
		return ""
	}
	v = html.UnescapeString(v)
	v = Dequote(v)
	return v
}

func getEnvBool(key string) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return false
	}
	v = html.UnescapeString(v)
	v = Dequote(v)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}
