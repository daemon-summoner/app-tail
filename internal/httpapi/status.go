// SPDX-License-Identifier: MIT

package httpapi

import "net/http"

// statusApproveByHand is the answer for a machine where approving a network change takes a
// command app-tail cannot run itself. HTTP's 501 fits: the request is valid, and this server
// cannot carry it out.
const statusApproveByHand = http.StatusNotImplemented
