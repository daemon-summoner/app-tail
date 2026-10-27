// SPDX-License-Identifier: MIT

package autostart

import (
	"fmt"
	"strings"
	"unicode/utf16"
)

// The renderers below are deliberately free of build constraints. Each one is only
// invoked by its own platform, but keeping them here means every template is compiled
// and golden-tested on every machine -- a broken systemd unit is otherwise invisible
// until someone runs the app on Linux.

// launchdProcessType is the resource class launchd gives the agent. Every packet the
// forwards, the proxy and the network interface carry is relayed by this process, so a
// throttled class is felt as lag in each interactive session: under Background, macOS
// confines the agent to the efficiency cores at the lowest priority, and a machine busy
// with a build holds keystrokes over SSH for seconds.
const launchdProcessType = "Interactive"

// plist renders the macOS LaunchAgent. RunAtLoad starts it at login; KeepAlive with
// SuccessfulExit=false restarts it after a crash but respects a deliberate quit.
func (m *Manager) plist() string {
	var args strings.Builder
	for _, arg := range m.command() {
		fmt.Fprintf(&args, "\t\t<string>%s</string>\n", escapeXML(arg))
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
%s	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>%s</string>
</dict>
</plist>
`, escapeXML(Label), args.String(), launchdProcessType)
}

// systemdUnit renders the Linux user service.
func (m *Manager) systemdUnit() string {
	return fmt.Sprintf(`[Unit]
Description=app-tail userspace Tailscale port forwarder
Documentation=https://github.com/sellitus/app-tail
After=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`, escapeExec(m.command()))
}

// windowsRunValue renders the string stored under the HKCU Run key.
func (m *Manager) windowsRunValue() string {
	return escapeWindowsArgs(m.command())
}

// TaskName is the Windows scheduled task that starts app-tail with administrator
// rights. It sits in the root folder, where an operator opening Task Scheduler sees it
// without expanding anything.
const TaskName = `\` + ServiceName

// windowsTaskXML renders the scheduled task that starts app-tail elevated at logon.
//
// The task exists for one reason: a login item that starts the interface mode without
// administrator rights would put a consent prompt on screen at every single login, which
// is the outcome this app is built to avoid. Only the interface mode installs it; the
// contained mode keeps the registry value, which needs no rights at all.
//
// userID is the account the task runs as, given as a SID rather than a name: a name is
// domain- and locale-dependent, and a task registered against one that does not resolve
// is accepted and then never runs.
func (m *Manager) windowsTaskXML(userID string) string {
	args := escapeWindowsArgs(m.Args)
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Starts app-tail with the administrator rights its network-interface mode needs.</Description>
    <URI>%s</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>%s</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>%s</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>
`, escapeXML(TaskName), escapeXML(userID), escapeXML(userID), escapeXML(m.ExecPath), escapeXML(args))
}

// BootRepairTaskName is the Windows scheduled task that puts this machine's resolver back
// at boot, from whatever a run that never shut down left pointed at app-tail.
const BootRepairTaskName = `\` + ServiceName + ` DNS repair`

// bootRepairTaskXML renders the task that runs `app-tail dns restore` at boot and at logon.
//
// Windows has no helper starting at boot to do this, so without it a crash or power cut
// with System DNS on leaves every adapter asking an address nothing listens on until
// somebody opens app-tail. It runs as SYSTEM because nobody has logged in yet. The run at
// boot puts back what the record names; the one two minutes later finds adapters the record
// lost, which Windows lists only once they have an address; the one at logon covers a Fast
// Startup power-on, which is not a boot. None repeats, and every run stands back for an
// app-tail serving the machine, which holds the resolver's serving lock.
func bootRepairTaskXML(execPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Puts this machine's DNS settings back at boot if app-tail stopped without doing it.</Description>
    <URI>%s</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT2M</Delay>
    </BootTrigger>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <Arguments>dns restore</Arguments>
    </Exec>
  </Actions>
</Task>
`, escapeXML(BootRepairTaskName), escapeXML(execPath))
}

// utf16LE encodes a task definition the way schtasks reads one back.
//
// The tool takes the encoding from the byte-order mark and nothing else: a definition
// written as UTF-8 is rejected as malformed even when every character in it is ASCII,
// with a message that names no line and no field.
func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2+2*len(units))
	out = append(out, 0xFF, 0xFE) // the byte-order mark, which is what selects the encoding
	for _, unit := range units {
		out = append(out, byte(unit), byte(unit>>8))
	}
	return out
}

// escapeXML escapes the five XML entities so a path containing an ampersand cannot
// produce an unparsable plist.
func escapeXML(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(s)
}

// escapeExec renders an argument list for a systemd ExecStart line. systemd splits on
// whitespace and interprets backslashes, so both must be quoted and escaped.
func escapeExec(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "" || strings.ContainsAny(arg, " \t\"\\'") {
			escaped := strings.ReplaceAll(arg, `\`, `\\`)
			escaped = strings.ReplaceAll(escaped, `"`, `\"`)
			quoted = append(quoted, `"`+escaped+`"`)
			continue
		}
		quoted = append(quoted, arg)
	}
	return strings.Join(quoted, " ")
}

// escapeWindowsArgs renders an argument list the way the Windows command-line parser
// reads it back.
func escapeWindowsArgs(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, escapeWindowsArg(arg))
	}
	return strings.Join(quoted, " ")
}

// escapeWindowsArg quotes one argument by the rules the Windows parser actually applies:
// inside quotes a backslash is ordinary except immediately before a quote, where a run of
// them is halved and an odd one escapes the quote. So every backslash run that meets a quote
// -- including the closing one this adds -- has to be doubled first.
//
// A path ending in a separator is the case that matters, and it is the common one here:
// quoting C:\Program Files\app-tail\ as-is ends the argument with \" , which the parser reads
// as an escaped quote and the login item then starts a program named by the rest of the line.
func escapeWindowsArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if !strings.ContainsAny(arg, " \t\"") {
		return arg
	}
	var out strings.Builder
	out.WriteByte('"')
	slashes := 0
	for i := 0; i < len(arg); i++ {
		switch c := arg[i]; c {
		case '\\':
			slashes++
			out.WriteByte(c)
		case '"':
			out.WriteString(strings.Repeat(`\`, slashes+1))
			slashes = 0
			out.WriteByte(c)
		default:
			slashes = 0
			out.WriteByte(c)
		}
	}
	out.WriteString(strings.Repeat(`\`, slashes))
	out.WriteByte('"')
	return out.String()
}
