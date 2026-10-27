// SPDX-License-Identifier: MIT

package config

import "github.com/sellitus/app-tail/internal/fileown"

// restrictToOwner narrows a config file to the account that owns it: these hold auth keys
// and OAuth secrets, and Windows hands a new file whatever its parent directory carries.
// Everywhere else the mode bits the file was created with already carry it.
func restrictToOwner(path string) error { return fileown.RestrictToOwner(path) }
