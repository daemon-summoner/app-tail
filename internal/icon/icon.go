// SPDX-License-Identifier: MIT

// Package icon draws the app-tail mark: the tray icon, the status dot it carries, and
// the application icon the macOS bundle ships.
//
// The artwork is generated from a pixel map rather than shipped as a binary blob, so
// the mark stays reviewable and editable in source and every size comes from one
// source of truth. Pixel art is the reason this stays cheap: the map is scaled by
// whole multiples, so no size is ever a blurred resample of another.
package icon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"sync"
)

// Grid is the width and height of the pixel map every rendering scales from.
const Grid = 32

// TraySize is the pixel size of the tray icon. It renders the grid 1:1, and is the
// width the ICO directory entry declares.
const TraySize = Grid

// cornerRadius rounds the application icon's backdrop, in grid cells. It matches the
// dashboard favicon's 7-of-32 and sits close enough to Apple's icon curve that the
// bundle reads as a native app among system icons.
const cornerRadius = 7

// The generator runs with this package as its working directory, so the dashboard's
// favicon is named relative to it.
//go:generate go run ./gen favicon ../../ui/public/favicon.svg

// squid is the mark, one character per pixel:
//
//	T body   L highlight   D shade   W eye white   K pupil   P cheek   . transparent
var squid = [Grid]string{
	"................................",
	"................................",
	"................................",
	"................................",
	"...........TTTTTTTTTT...........",
	".........TTTTLLLLLLTTTT.........",
	"........TTTTLLLLLTTTTTTT........",
	".......TTTLLLLTTTTTTTTTTT.......",
	".......TTLLLTTTTTTTTTTTTT.......",
	".......TTTWWWWWTTWWWWWTTT.......",
	".......TTTWKKKKTTWKKKKTTT.......",
	".......TTTWKWKKTTWKWKKTTT.......",
	".......TTTWKKKKTTWKKKKTTT.......",
	".......TPPWKKKKTTWKKKKPPT.......",
	".......TPPWWWWWTTWWWWWPPT.......",
	".......TTTTTTTTTTTTTDDDDD.......",
	".......TTTTTTTTTTTTDDDDDD.......",
	"........TTTTTTTTTTTDDDDD........",
	".......TT..TT..TT..TT..TT.......",
	".......TT..TT..TT..TT..TT.......",
	".......TT..TT..TT..TT..TT.......",
	".......TT..TT..TT..TT..TT.......",
	"......TT...TT..TT..TT...TT......",
	"......TT...TT..TT..TT...TT......",
	"......DD...TT..TT..TT...DD......",
	"...........TT..TT..TT...........",
	"...........DD..DD..DD...........",
	"...........DD..DD..DD...........",
	"................................",
	"................................",
	"................................",
	"................................",
}

// bubbles are the drifting specks that appear on the application icon only. They read
// as decoration at 512px and as dirt at tray size, so the tray mark leaves them out.
// Each keeps clear air on every side: a bubble touching the head stops reading as a
// bubble and becomes a lump growing out of it.
var bubbles = []struct{ x, y, size int }{
	{26, 4, 3},
	{4, 9, 2},
	{2, 13, 1},
}

// Palette. The mark is built from Tailwind's teal ramp so it matches the dashboard,
// whose accent is the same teal-300.
var (
	body        = color.NRGBA{R: 0x2D, G: 0xD4, B: 0xBF, A: 0xFF} // teal-400
	highlight   = color.NRGBA{R: 0x5E, G: 0xEA, B: 0xD4, A: 0xFF} // teal-300
	shade       = color.NRGBA{R: 0x14, G: 0xB8, B: 0xA6, A: 0xFF} // teal-500
	eyeWhite    = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	pupil       = color.NRGBA{R: 0x0F, G: 0x17, B: 0x2A, A: 0xFF} // slate-900
	cheek       = color.NRGBA{R: 0xFD, G: 0xA4, B: 0xAF, A: 0xFF} // rose-300
	bubble      = color.NRGBA{R: 0x67, G: 0xE8, B: 0xF9, A: 0xFF} // cyan-300
	backdrop    = color.NRGBA{R: 0x1E, G: 0x29, B: 0x3B, A: 0xFF} // slate-800
	transparent = color.NRGBA{}
)

var marks = map[byte]color.NRGBA{
	'T': body,
	'L': highlight,
	'D': shade,
	'W': eyeWhite,
	'K': pupil,
	'P': cheek,
	'.': transparent,
}

// Status is the health the tray dot reports.
type Status int

const (
	// StatusStarting is the state before the node has settled either way. It is
	// deliberately not a fault: a red dot on every launch is an alarm the user learns
	// to ignore, which costs the indicator its only job.
	StatusStarting Status = iota
	// StatusHealthy means connected with every enabled forward actually listening.
	StatusHealthy
	// StatusFault means disconnected, an enabled forward is down, or an action failed.
	StatusFault
)

// Status dot colours. These are deliberately more saturated than the mark's own
// palette: the dot is a few pixels wide in a menu bar and has to survive being read
// at a glance against both a light and a dark background.
var (
	dotHealthy  = color.NRGBA{R: 0x20, G: 0xDC, B: 0xFF, A: 0xFF} // vivid cyan
	dotFault    = color.NRGBA{R: 0xBD, G: 0x5A, B: 0xFF, A: 0xFF} // electric purple
	dotStarting = color.NRGBA{R: 0x94, G: 0xA3, B: 0xB8, A: 0xFF} // slate-400
)

// dot is the colour each status paints into the badge.
func (s Status) dot() color.NRGBA {
	switch s {
	case StatusHealthy:
		return dotHealthy
	case StatusFault:
		return dotFault
	default:
		return dotStarting
	}
}

// String names the status for logs and test failures.
func (s Status) String() string {
	switch s {
	case StatusHealthy:
		return "healthy"
	case StatusFault:
		return "fault"
	default:
		return "starting"
	}
}

// badge is the status dot, a disc taking the status colour. It is sized to survive a
// menu bar: a smaller dot reads as an artefact of the mark rather than as a light.
var badge = []string{
	".#####.",
	"#######",
	"#######",
	"#######",
	"#######",
	"#######",
	".#####.",
}

// badgeX and badgeY place the dot in the lower-right corner. The mark's tentacles stop
// short of it, so the dot needs no cleared gap to stay legible against them --
// TestTheBadgeSitsWhereTheMarkIsNot pins that, since a tentacle grown into this corner
// would merge with the dot into one unreadable blob.
const badgeX, badgeY = 25, 25

// Mark renders the tray icon: the squid on transparency with the status dot stamped
// into its corner, at Grid resolution so the tray draws it without resampling.
func Mark(s Status) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, Grid, Grid))
	for y, row := range squid {
		for x := 0; x < Grid; x++ {
			if c := marks[row[x]]; c.A != 0 {
				img.SetNRGBA(x, y, c)
			}
		}
	}
	stampBadge(img, s)
	return img
}

// stampBadge paints the status dot into img.
func stampBadge(img *image.NRGBA, s Status) {
	fill := s.dot()
	for dy, row := range badge {
		for dx := 0; dx < len(row); dx++ {
			if row[dx] != '#' {
				continue
			}
			if x, y := badgeX+dx, badgeY+dy; x < Grid && y < Grid {
				img.SetNRGBA(x, y, fill)
			}
		}
	}
}

// masterSize is the resolution the application icon is composed at before being
// reduced. Every size an .iconset asks for divides it exactly, so each one is a clean
// box filter of the same master rather than an independently rounded redraw.
const masterSize = 2048

// AppIcon renders the application icon at px: the mark over the rounded slate
// backdrop, with bubbles. px must divide masterSize, which every macOS iconset size
// does; other values panic rather than silently returning a blurred icon.
func AppIcon(px int) *image.NRGBA {
	if px <= 0 || masterSize%px != 0 {
		panic(fmt.Sprintf("icon: application icon size must divide %d, got %d", masterSize, px))
	}
	return reduce(master(), masterSize/px)
}

// master composes the icon at masterSize with hard edges. The corner rounding is left
// jagged here on purpose: the reduction that follows is what anti-aliases it, so the
// curve is resolved once, by the same filter, at every output size.
func master() *image.NRGBA {
	const scale = masterSize / Grid
	img := image.NewNRGBA(image.Rect(0, 0, masterSize, masterSize))

	radius := masterSize * cornerRadius / Grid
	for y := 0; y < masterSize; y++ {
		for x := 0; x < masterSize; x++ {
			if insideRounded(x, y, masterSize, radius) {
				img.SetNRGBA(x, y, backdrop)
			}
		}
	}

	for _, b := range bubbles {
		fillCells(img, b.x, b.y, b.size, b.size, scale, bubble)
	}
	for y, row := range squid {
		for x := 0; x < Grid; x++ {
			if c := marks[row[x]]; c.A != 0 {
				fillCells(img, x, y, 1, 1, scale, c)
			}
		}
	}
	return img
}

// fillCells paints a w x h block of grid cells at the given scale.
func fillCells(img *image.NRGBA, gx, gy, w, h, scale int, c color.NRGBA) {
	for y := gy * scale; y < (gy+h)*scale; y++ {
		for x := gx * scale; x < (gx+w)*scale; x++ {
			img.SetNRGBA(x, y, c)
		}
	}
}

// insideRounded reports whether (x,y) falls inside a size x size square whose corners
// are rounded to the given radius.
func insideRounded(x, y, size, radius int) bool {
	// Clamping to the nearest corner centre collapses both cases into one test: along
	// a straight edge the clamp lands on the point itself, leaving a distance of zero
	// on that axis, and only in a corner does it measure a real radius.
	ox := clamp(x, radius, size-1-radius)
	oy := clamp(y, radius, size-1-radius)
	dx, dy := x-ox, y-oy
	return dx*dx+dy*dy <= radius*radius
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// reduce box-filters img down by an integer factor, averaging in straight (premultiplied)
// space so the transparent surround does not bleed dark edges into the artwork.
func reduce(src *image.NRGBA, factor int) *image.NRGBA {
	if factor == 1 {
		return src
	}
	w := src.Bounds().Dx() / factor
	h := src.Bounds().Dy() / factor
	dst := image.NewNRGBA(image.Rect(0, 0, w, h))
	area := factor * factor
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var r, g, b, a int
			for sy := 0; sy < factor; sy++ {
				for sx := 0; sx < factor; sx++ {
					c := src.NRGBAAt(x*factor+sx, y*factor+sy)
					// Weight colour by alpha so fully transparent pixels contribute
					// no colour, only their (zero) coverage.
					r += int(c.R) * int(c.A)
					g += int(c.G) * int(c.A)
					b += int(c.B) * int(c.A)
					a += int(c.A)
				}
			}
			if a == 0 {
				dst.SetNRGBA(x, y, transparent)
				continue
			}
			dst.SetNRGBA(x, y, color.NRGBA{
				R: uint8(r / a),
				G: uint8(g / a),
				B: uint8(b / a),
				A: uint8(a / area),
			})
		}
	}
	return dst
}

// statuses is every value a Status may hold. Rendering is driven off it so a status
// added without a rendering is a compile-time-visible omission rather than a blank icon.
var statuses = []Status{StatusStarting, StatusHealthy, StatusFault}

// trayPNGs holds one encoding per status. The tray repaints on every refresh tick and
// the bytes never change, so all three are encoded once on first use.
var trayPNGs = sync.OnceValue(func() map[Status][]byte {
	m := make(map[Status][]byte, len(statuses))
	for _, s := range statuses {
		m[s] = encode(Mark(s))
	}
	return m
})

// PNG is the tray icon macOS and Linux take.
func PNG(s Status) []byte {
	if b, ok := trayPNGs()[s]; ok {
		return b
	}
	// dot() paints any unrecognised status in the neutral starting colour; PNG follows
	// it, so a status added without a rendering shows that rather than nothing at all.
	return trayPNGs()[StatusStarting]
}

// AppIconPNG encodes the application icon at px.
func AppIconPNG(px int) []byte { return encode(AppIcon(px)) }

// WindowsIconSizes are the renderings embedded in the .exe's resource section, which
// is what Explorer, the taskbar and Alt-Tab draw.
//
// 48 is deliberately absent even though Windows has a slot for it: 48 is neither a
// multiple of Grid nor a whole division of it, so a 48px rendering would give some
// cells two pixels and others one. Windows scales the 256 down for that slot instead,
// which at least treats every cell alike.
func WindowsIconSizes() []int { return []int{16, 32, 64, 128, 256} }

// IconsetFile is one rendering in a macOS .iconset directory.
type IconsetFile struct {
	// Name is the filename iconutil looks for, including the @2x suffix convention.
	Name string
	// Px is the pixel size that file holds, which for an @2x entry is twice the
	// point size its name states.
	Px int
}

// IconsetFiles is the full set iconutil needs to build an .icns. macOS picks a
// different entry for each surface -- the Dock, a Finder list row, Get Info, the
// Cmd-Tab switcher -- so an incomplete set makes iconutil refuse the directory
// outright rather than substituting a nearby size.
func IconsetFiles() []IconsetFile {
	return []IconsetFile{
		{Name: "icon_16x16.png", Px: 16},
		{Name: "icon_16x16@2x.png", Px: 32},
		{Name: "icon_32x32.png", Px: 32},
		{Name: "icon_32x32@2x.png", Px: 64},
		{Name: "icon_128x128.png", Px: 128},
		{Name: "icon_128x128@2x.png", Px: 256},
		{Name: "icon_256x256.png", Px: 256},
		{Name: "icon_256x256@2x.png", Px: 512},
		{Name: "icon_512x512.png", Px: 512},
		{Name: "icon_512x512@2x.png", Px: 1024},
	}
}

// encode writes a PNG. png.Encode only fails on a writer error, and a bytes.Buffer
// has none, so a failure here is a corrupt build rather than a runtime condition.
func encode(img image.Image) []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic("icon: encoding the built-in icon failed: " + err.Error())
	}
	return buf.Bytes()
}

// ICO wraps the tray PNG in an ICO container, which is what the Windows shell wants.
// Windows Vista and later read PNG-compressed icon entries directly, so no bitmap
// re-encoding is needed.
func ICO(s Status) []byte {
	payload := PNG(s)

	const headerLen = 6
	const entryLen = 16

	le := binary.LittleEndian
	out := make([]byte, 0, headerLen+entryLen+len(payload))
	// ICONDIR: reserved, type 1 (icon), one image.
	out = le.AppendUint16(out, 0)
	out = le.AppendUint16(out, 1)
	out = le.AppendUint16(out, 1)
	// ICONDIRENTRY: width, height, palette size, reserved, planes, bit depth.
	out = append(out, TraySize, TraySize, 0, 0)
	out = le.AppendUint16(out, 1)
	out = le.AppendUint16(out, 32)
	out = le.AppendUint32(out, uint32(len(payload)))
	out = le.AppendUint32(out, headerLen+entryLen)

	return append(out, payload...)
}
