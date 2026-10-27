// SPDX-License-Identifier: MIT

package icon

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"image"
	"image/color"
	"image/png"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// An icon that fails to decode leaves an invisible or blank tray entry, which looks
// exactly like the app failing to start.
func TestTheTrayPNGDecodesAtTheSizeTheTrayExpects(t *testing.T) {
	for _, s := range statuses {
		t.Run(s.String(), func(t *testing.T) {
			img, err := png.Decode(bytes.NewReader(PNG(s)))
			if err != nil {
				t.Fatalf("the built-in icon is not decodable PNG: %v", err)
			}
			if b := img.Bounds(); b.Dx() != TraySize || b.Dy() != TraySize {
				t.Errorf("icon is %dx%d, want %dx%d", b.Dx(), b.Dy(), TraySize, TraySize)
			}
		})
	}
}

// A fully transparent icon decodes cleanly and shows nothing at all, so the mark
// itself has to be asserted, not just the container.
func TestTheMarkCoversEnoughOfTheSquareToBeSeenWithoutFillingIt(t *testing.T) {
	for _, s := range statuses {
		t.Run(s.String(), func(t *testing.T) {
			opaque := countIf(Mark(s), func(c color.NRGBA) bool { return c.A > 0 })
			total := Grid * Grid
			if opaque == 0 {
				t.Fatal("the icon is entirely transparent and would show nothing")
			}
			// A mark covering the whole square is a filled box, not a glyph; one
			// covering almost nothing is invisible at menu-bar size.
			if opaque > total*2/3 {
				t.Errorf("the icon covers %d of %d pixels, which is a solid block rather than a mark", opaque, total)
			}
			if opaque < total/20 {
				t.Errorf("the icon covers only %d of %d pixels and would be invisible in a tray", opaque, total)
			}
		})
	}
}

// The dot is the entire reason the tray icon is status-aware. Two statuses rendering
// the same pixels would leave a user staring at an indicator that never moves.
func TestEveryStatusPaintsItsOwnDotColour(t *testing.T) {
	seen := map[color.NRGBA]Status{}
	for _, s := range statuses {
		img := Mark(s)
		// The disc's centre is filled whatever its outline, so comparing there does not
		// depend on the badge's exact shape.
		got := img.NRGBAAt(badgeX+3, badgeY+3)
		if got.A != 0xFF {
			t.Errorf("%v: the dot centre is not opaque: %+v", s, got)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("%v paints the same dot as %v (%+v), so the two are indistinguishable", s, prev, got)
		}
		seen[got] = s
	}
}

// The dot carries no cleared ring, so its legibility rests entirely on landing where
// the mark does not draw. A tentacle extended into this corner, or a dot nudged up
// into the face, would merge the two into one unreadable blob at menu-bar size --
// which is a design change, not a bug, and has to be made deliberately.
func TestTheBadgeSitsWhereTheMarkIsNot(t *testing.T) {
	for dy, row := range badge {
		for dx := range row {
			if row[dx] != '#' {
				continue
			}
			x, y := badgeX+dx, badgeY+dy
			if x >= Grid || y >= Grid {
				t.Fatalf("the dot pixel at (%d,%d) falls outside the %dx%d grid", x, y, Grid, Grid)
			}
			if marks[squid[y][x]].A != 0 {
				t.Errorf("the dot covers the mark at (%d,%d)", x, y)
			}
		}
	}
}

// Everything outside the dot's own box belongs to the mark. A badge that wrote beyond
// it would erase artwork with no visible cause anywhere in the pixel map.
func TestStampingTheDotLeavesTheRestOfTheMarkUntouched(t *testing.T) {
	plain := image.NewNRGBA(image.Rect(0, 0, Grid, Grid))
	for y, row := range squid {
		for x := 0; x < Grid; x++ {
			if c := marks[row[x]]; c.A != 0 {
				plain.SetNRGBA(x, y, c)
			}
		}
	}
	stamped := Mark(StatusHealthy)

	for y := 0; y < Grid; y++ {
		for x := 0; x < Grid; x++ {
			if x >= badgeX && x < badgeX+len(badge[0]) && y >= badgeY && y < badgeY+len(badge) {
				continue
			}
			if plain.NRGBAAt(x, y) != stamped.NRGBAAt(x, y) {
				t.Fatalf("the badge changed the pixel at (%d,%d), which is outside its own box", x, y)
			}
		}
	}
}

// Windows reads the directory entry to find the image; a wrong offset or length
// yields a blank notification-area slot with no error anywhere.
func TestTheICOWrapsThePNGWithAHeaderWindowsCanFollow(t *testing.T) {
	for _, s := range statuses {
		t.Run(s.String(), func(t *testing.T) {
			ico := ICO(s)
			payload := PNG(s)

			if len(ico) < 22 {
				t.Fatalf("ICO is %d bytes, too short to hold a header and a directory entry", len(ico))
			}
			if got := binary.LittleEndian.Uint16(ico[0:2]); got != 0 {
				t.Errorf("ICO reserved field = %d, want 0", got)
			}
			if got := binary.LittleEndian.Uint16(ico[2:4]); got != 1 {
				t.Errorf("ICO type = %d, want 1 (icon)", got)
			}
			if got := binary.LittleEndian.Uint16(ico[4:6]); got != 1 {
				t.Errorf("ICO image count = %d, want 1", got)
			}
			if got := ico[6]; got != TraySize {
				t.Errorf("ICO entry width = %d, want %d", got, TraySize)
			}
			if got := ico[7]; got != TraySize {
				t.Errorf("ICO entry height = %d, want %d", got, TraySize)
			}

			size := binary.LittleEndian.Uint32(ico[14:18])
			offset := binary.LittleEndian.Uint32(ico[18:22])
			if int(offset)+int(size) != len(ico) {
				t.Fatalf("entry points at bytes [%d,%d) of a %d-byte file", offset, int(offset)+int(size), len(ico))
			}
			if !bytes.Equal(ico[offset:offset+size], payload) {
				t.Error("the ICO payload is not the PNG the directory entry describes")
			}
			if _, err := png.Decode(bytes.NewReader(ico[offset : offset+size])); err != nil {
				t.Errorf("the embedded ICO payload is not decodable: %v", err)
			}
		})
	}
}

// PNG hands out a cached slice. A caller that mutated it would corrupt the icon for
// every later repaint, so the cache must not be a shared mutable buffer by accident.
func TestTheTrayPNGIsStableAcrossCalls(t *testing.T) {
	for _, s := range statuses {
		first := append([]byte(nil), PNG(s)...)
		if !bytes.Equal(first, PNG(s)) {
			t.Errorf("%v: two calls to PNG returned different bytes", s)
		}
	}
}

// A Status added without a rendering must still produce an icon. Returning nothing
// would leave the menu bar with a blank slot -- the app looks as though it failed to
// start -- for what is only a missing entry in the palette.
func TestAStatusWithNoRenderingFallsBackToTheNeutralOne(t *testing.T) {
	got := PNG(Status(len(statuses) + 7))
	if got == nil {
		t.Fatal("an unrecognised status produced no icon at all")
	}
	if !bytes.Equal(got, PNG(StatusStarting)) {
		t.Error("an unrecognised status does not fall back to the neutral starting icon")
	}
}

// Every size in the macOS iconset comes from one master render. A size that does not
// divide it would be a rounded resample, which is what makes pixel art look blurred.
func TestTheApplicationIconRendersEveryIconsetSize(t *testing.T) {
	// The sizes macOS asks for, including the @2x variants.
	for _, px := range []int{16, 32, 64, 128, 256, 512, 1024} {
		t.Run(strconv.Itoa(px), func(t *testing.T) {
			if masterSize%px != 0 {
				t.Fatalf("%d does not divide the master render (%d), so it would be resampled", px, masterSize)
			}
			img := AppIcon(px)
			if b := img.Bounds(); b.Dx() != px || b.Dy() != px {
				t.Fatalf("AppIcon(%d) is %dx%d", px, b.Dx(), b.Dy())
			}
			if _, err := png.Decode(bytes.NewReader(AppIconPNG(px))); err != nil {
				t.Errorf("AppIconPNG(%d) is not decodable: %v", px, err)
			}
		})
	}
}

// An @2x entry holding its point size rather than twice it renders as a soft, wrongly
// scaled icon on every Retina display -- and on nothing else, so it survives a look
// at the machine it was built on.
func TestEveryRetinaIconsetEntryHoldsTwiceItsPointSize(t *testing.T) {
	byName := map[string]int{}
	for _, f := range IconsetFiles() {
		if _, dup := byName[f.Name]; dup {
			t.Errorf("%s appears twice in the iconset", f.Name)
		}
		byName[f.Name] = f.Px
		if masterSize%f.Px != 0 {
			t.Errorf("%s asks for %dpx, which does not divide the master render", f.Name, f.Px)
		}
	}
	for name, px := range byName {
		base, isRetina := strings.CutSuffix(strings.TrimSuffix(name, ".png"), "@2x")
		if !isRetina {
			continue
		}
		basePx, ok := byName[base+".png"]
		if !ok {
			t.Errorf("%s has no %s.png beside it", name, base)
			continue
		}
		if px != basePx*2 {
			t.Errorf("%s is %dpx against a base of %dpx, want %dpx", name, px, basePx, basePx*2)
		}
	}
}

// Pixel art only survives whole-number scaling. A size that is neither a multiple of
// the grid nor a whole division of it gives some cells more output pixels than others,
// so the mark comes out visibly lopsided -- the reason 48 is not among the Windows
// sizes even though Windows has a slot for it.
func TestEveryShippedSizeScalesTheGridEvenly(t *testing.T) {
	sizes := map[string][]int{"windows": WindowsIconSizes()}
	for _, f := range IconsetFiles() {
		sizes["iconset"] = append(sizes["iconset"], f.Px)
	}

	for platform, list := range sizes {
		for _, px := range list {
			t.Run(platform+"/"+strconv.Itoa(px), func(t *testing.T) {
				if px%Grid != 0 && Grid%px != 0 {
					t.Errorf("%dpx neither scales the %d-cell grid up nor divides it down evenly", px, Grid)
				}
				if masterSize%px != 0 {
					t.Errorf("%dpx does not divide the master render, so AppIcon refuses it", px)
				}
			})
		}
	}
}

func TestAnApplicationIconSizeThatWouldBlurIsRefusedRatherThanRendered(t *testing.T) {
	for _, px := range []int{0, -1, 100, 3} {
		t.Run(strconv.Itoa(px), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("AppIcon(%d) returned a blurred icon instead of refusing", px)
				}
			}()
			AppIcon(px)
		})
	}
}

// The backdrop is what makes the icon a macOS app icon rather than a floating sprite.
// Losing the rounding leaves a hard square that reads as broken among system icons.
func TestTheApplicationIconIsAnOpaqueRoundedSquare(t *testing.T) {
	img := AppIcon(512)

	// The centre of each edge is inside the shape; the very corners are outside it.
	for _, p := range []image.Point{{X: 256, Y: 1}, {X: 256, Y: 510}, {X: 1, Y: 256}, {X: 510, Y: 256}} {
		if c := img.NRGBAAt(p.X, p.Y); c.A != 0xFF {
			t.Errorf("the edge midpoint (%d,%d) is not opaque: %+v", p.X, p.Y, c)
		}
	}
	for _, p := range []image.Point{{X: 0, Y: 0}, {X: 511, Y: 0}, {X: 0, Y: 511}, {X: 511, Y: 511}} {
		if c := img.NRGBAAt(p.X, p.Y); c.A != 0 {
			t.Errorf("the corner (%d,%d) is not rounded away: %+v", p.X, p.Y, c)
		}
	}
}

// The corner is anti-aliased by the reduction rather than drawn smooth, so a partly
// covered pixel is the evidence that reduction ran. A curve of hard on/off pixels is
// a staircase, which is the visible symptom of the master render being skipped.
func TestTheReducedCornerIsAntiAliasedRatherThanStaircased(t *testing.T) {
	img := AppIcon(512)
	var partial int
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			if a := img.NRGBAAt(x, y).A; a > 0 && a < 0xFF {
				partial++
			}
		}
	}
	if partial == 0 {
		t.Error("no partly covered pixel in the top-left corner: the curve was not anti-aliased")
	}
}

// The bubbles are decoration, and decoration touching the head stops reading as
// decoration. This is geometry the eye catches instantly and a size assertion never
// would, so it is pinned on the grid rather than in the render.
func TestEveryBubbleKeepsClearAirAroundIt(t *testing.T) {
	for _, b := range bubbles {
		for y := b.y - 1; y <= b.y+b.size; y++ {
			for x := b.x - 1; x <= b.x+b.size; x++ {
				inside := x >= b.x && x < b.x+b.size && y >= b.y && y < b.y+b.size
				if inside || y < 0 || y >= Grid || x < 0 || x >= Grid {
					continue
				}
				if marks[squid[y][x]].A != 0 {
					t.Errorf("the bubble at (%d,%d) touches the mark at (%d,%d)", b.x, b.y, x, y)
				}
			}
		}
	}
}

// A bubble the rounded corner cuts through renders as a wedge stuck to the edge.
func TestEveryBubbleFallsInsideTheRoundedBackdrop(t *testing.T) {
	const scale = masterSize / Grid
	radius := masterSize * 7 / Grid
	for _, b := range bubbles {
		// Only the block's own corners can fall outside a convex shape.
		corners := []image.Point{
			{X: b.x * scale, Y: b.y * scale},
			{X: (b.x+b.size)*scale - 1, Y: b.y * scale},
			{X: b.x * scale, Y: (b.y+b.size)*scale - 1},
			{X: (b.x+b.size)*scale - 1, Y: (b.y+b.size)*scale - 1},
		}
		for _, p := range corners {
			if !insideRounded(p.X, p.Y, masterSize, radius) {
				t.Errorf("the bubble at (%d,%d) is clipped by the rounded corner", b.x, b.y)
			}
		}
	}
}

// The app icon and the tray mark are the same artwork; a drift between them means one
// of the two was edited alone and the app stops looking like itself in one place.
func TestTheApplicationIconDrawsTheSameMarkAsTheTray(t *testing.T) {
	img := AppIcon(Grid)
	for y, row := range squid {
		for x := 0; x < Grid; x++ {
			want := marks[row[x]]
			if want.A == 0 {
				continue
			}
			if got := img.NRGBAAt(x, y); got != want {
				t.Fatalf("the mark pixel at (%d,%d) is %+v in the app icon, want %+v", x, y, got, want)
			}
		}
	}
}

// The pixel map is what every size is scaled from, so a row of the wrong length
// silently shifts or truncates the mark rather than failing to compile.
func TestThePixelMapIsSquareAndUsesOnlyKnownColours(t *testing.T) {
	for y, row := range squid {
		if len(row) != Grid {
			t.Fatalf("row %d is %d cells wide, want %d", y, len(row), Grid)
		}
		for x := 0; x < Grid; x++ {
			if _, ok := marks[row[x]]; !ok {
				t.Errorf("row %d column %d uses the unmapped character %q", y, x, row[x])
			}
		}
	}
}

// reduce averages in alpha-weighted space so a transparent surround contributes no
// colour. Averaging straight NRGBA instead darkens every edge with a grey halo, which
// is the classic symptom of a fringed icon.
func TestReducingAgainstTransparencyDoesNotDarkenTheEdge(t *testing.T) {
	src := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	white := color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	src.SetNRGBA(0, 0, white)

	// A factor of 1 is the identity; copying instead would silently double the memory
	// every AppIcon call holds.
	if same := reduce(src, 1); same != src {
		t.Error("reduce(src, 1) did not return the source image unchanged")
	}

	got := reduce(src, 2).NRGBAAt(0, 0)
	if got.R != 0xFF || got.G != 0xFF || got.B != 0xFF {
		t.Errorf("the reduced pixel is tinted %+v, want white with reduced coverage", got)
	}
	if got.A != 0x3F {
		t.Errorf("coverage = %d, want %d (one of four pixels covered)", got.A, 0x3F)
	}
}

// The favicon is emitted as runs of cells rather than one rect per pixel, so an
// off-by-one in the run length shifts or drops part of the mark. Painting the rects
// back onto a grid and comparing it to the pixel map is what catches that -- a length
// assertion on the file would not.
func TestTheSVGPaintsBackToExactlyThePixelMap(t *testing.T) {
	var doc struct {
		Rects []struct {
			X      int    `xml:"x,attr"`
			Y      int    `xml:"y,attr"`
			Width  int    `xml:"width,attr"`
			Height int    `xml:"height,attr"`
			Fill   string `xml:"fill,attr"`
		} `xml:"rect"`
	}
	if err := xml.Unmarshal(SVG(), &doc); err != nil {
		t.Fatalf("the favicon is not well-formed XML: %v", err)
	}
	if len(doc.Rects) == 0 {
		t.Fatal("the favicon carries no rects")
	}

	var got [Grid][Grid]string
	for _, r := range doc.Rects {
		for y := r.Y; y < r.Y+r.Height; y++ {
			for x := r.X; x < r.X+r.Width; x++ {
				if y >= 0 && y < Grid && x >= 0 && x < Grid {
					got[y][x] = r.Fill
				}
			}
		}
	}

	// Built in the renderer's own order -- backdrop, bubbles, mark -- and compared over
	// every cell, so a run that paints one cell too many fails as loudly as one that
	// paints too few.
	var want [Grid][Grid]string
	for y := 0; y < Grid; y++ {
		for x := 0; x < Grid; x++ {
			want[y][x] = hex(backdrop)
		}
	}
	for _, b := range bubbles {
		for y := b.y; y < b.y+b.size; y++ {
			for x := b.x; x < b.x+b.size; x++ {
				want[y][x] = hex(bubble)
			}
		}
	}
	for y, row := range squid {
		for x := 0; x < Grid; x++ {
			if c := marks[row[x]]; c.A != 0 {
				want[y][x] = hex(c)
			}
		}
	}

	for y := 0; y < Grid; y++ {
		for x := 0; x < Grid; x++ {
			if got[y][x] != want[y][x] {
				t.Fatalf("the svg paints (%d,%d) as %q, want %q", x, y, got[y][x], want[y][x])
			}
		}
	}
}

// A colour written as anything but #rrggbb is ignored by the browser, which falls back
// to black and renders the mark as a silhouette.
func TestSVGColoursAreWrittenInTheFormBrowsersRead(t *testing.T) {
	valid := regexp.MustCompile(`^#[0-9a-f]{6}$`)
	for _, c := range []color.NRGBA{body, highlight, shade, eyeWhite, pupil, cheek, bubble, backdrop} {
		if got := hex(c); !valid.MatchString(got) {
			t.Errorf("hex(%+v) = %q, which is not a six-digit hex colour", c, got)
		}
	}
	// Leading zeros are the case a %x without width silently drops.
	if got := hex(color.NRGBA{R: 0x0F, G: 0x01, B: 0x00, A: 0xFF}); got != "#0f0100" {
		t.Errorf("hex dropped a leading zero: %q", got)
	}
}

func countIf(img *image.NRGBA, pred func(color.NRGBA) bool) int {
	var n int
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if pred(img.NRGBAAt(x, y)) {
				n++
			}
		}
	}
	return n
}
