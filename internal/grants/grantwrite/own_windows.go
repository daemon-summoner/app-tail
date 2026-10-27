// SPDX-License-Identifier: MIT

package grantwrite

import "github.com/sellitus/app-tail/internal/fileown"

// restrictDir narrows the folder to the administrators. A folder under ProgramData that
// already existed may have been made by a standard account, which could then replace the file.
func restrictDir(dir string) error { return fileown.RestrictTreeToAdministrators(dir) }
