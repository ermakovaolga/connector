package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"runtime"

	"fyne.io/systray"
)

var (
	colorOn   = color.RGBA{0x2e, 0xb8, 0x4b, 0xff}
	colorOff  = color.RGBA{0x8e, 0x8e, 0x93, 0xff}
	colorWarn = color.RGBA{0xf0, 0x9a, 0x1a, 0xff}
)

var iconCache = map[color.RGBA][]byte{}

// setIcon рисует кружок нужного цвета: PNG для macOS, ICO (с PNG внутри) для Windows.
func setIcon(c color.RGBA) {
	b, ok := iconCache[c]
	if !ok {
		b = circlePNG(c, 44) // 22pt @2x в строке меню macOS
		if runtime.GOOS == "windows" {
			b = pngToICO(circlePNG(c, 32), 32)
		}
		iconCache[c] = b
	}
	systray.SetIcon(b)
}

func circlePNG(c color.RGBA, size int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	r := float64(size) * 0.32
	cx := float64(size) / 2
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cx
			d := dx*dx + dy*dy
			switch {
			case d <= (r-0.5)*(r-0.5):
				img.Set(x, y, c)
			case d <= (r+0.5)*(r+0.5): // сглаживание края
				a := uint8(float64(c.A) * 0.5)
				img.Set(x, y, color.RGBA{uint8(uint16(c.R) * uint16(a) / 255), uint8(uint16(c.G) * uint16(a) / 255), uint8(uint16(c.B) * uint16(a) / 255), a})
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func pngToICO(p []byte, size int) []byte {
	var buf bytes.Buffer
	w := func(v any) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	w(uint16(0))
	w(uint16(1)) // icon
	w(uint16(1)) // 1 image
	buf.WriteByte(byte(size))
	buf.WriteByte(byte(size))
	buf.WriteByte(0)
	buf.WriteByte(0)
	w(uint16(1))  // planes
	w(uint16(32)) // bpp
	w(uint32(len(p)))
	w(uint32(6 + 16))
	buf.Write(p)
	return buf.Bytes()
}
