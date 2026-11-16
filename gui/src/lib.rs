#![no_std]
#![forbid(unsafe_code)]
// Experimental: standalone CPU renderer. Neither syscall ABI nor GPU/USB driver.

pub const MAX_WIDTH: usize = 4096;
pub const MAX_HEIGHT: usize = 2160;
pub const MAX_EVENTS_PER_FRAME: usize = 256;
pub const MAX_TEXT: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error { InvalidGeometry, BufferTooSmall, UnsupportedFormat }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat { Xrgb8888, Bgrx8888 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Surface {
    pub width: usize,
    pub height: usize,
    /// Byte count per scanline (may contain padding).
    pub stride: usize,
    pub format: PixelFormat,
}

impl Surface {
    pub fn required_bytes(self) -> Result<usize, Error> {
        if self.width == 0 || self.height == 0 ||
            self.width > MAX_WIDTH || self.height > MAX_HEIGHT {
            return Err(Error::InvalidGeometry);
        }
        let row = self.width.checked_mul(4).ok_or(Error::InvalidGeometry)?;
        if self.stride < row || self.stride % 4 != 0 {
            return Err(Error::InvalidGeometry);
        }
        self.stride.checked_mul(self.height).ok_or(Error::InvalidGeometry)
    }
}

pub struct Frame<'a> {
    pub surface: Surface,
    pixels: &'a mut [u8],
}
impl<'a> Frame<'a> {
    pub fn new(surface: Surface, pixels: &'a mut [u8]) -> Result<Self, Error> {
        let needed = surface.required_bytes()?;
        if pixels.len() < needed { return Err(Error::BufferTooSmall); }
        Ok(Self { surface, pixels })
    }
    pub fn bytes(&self) -> &[u8] { self.pixels }
    pub fn clear(&mut self, color: u32) {
        self.rect(0, 0, self.surface.width as i32, self.surface.height as i32, color);
    }
    pub fn pixel(&mut self, x: i32, y: i32, rgb: u32) {
        if x < 0 || y < 0 { return; }
        let (x, y) = (x as usize, y as usize);
        if x >= self.surface.width || y >= self.surface.height { return; }
        // Construction validates every dimension and stride. Still checked to
        // prevent accidental overflow if these methods change later.
        let Some(offset) = y.checked_mul(self.surface.stride)
            .and_then(|v| x.checked_mul(4).and_then(|a| v.checked_add(a))) else { return };
        let Some(end) = offset.checked_add(4) else { return };
        let Some(dest) = self.pixels.get_mut(offset..end) else { return };
        let [r, g, b] = [((rgb >> 16) & 255) as u8, ((rgb >> 8) & 255) as u8, (rgb & 255) as u8];
        match self.surface.format {
            PixelFormat::Xrgb8888 => dest.copy_from_slice(&[b, g, r, 0]),
            PixelFormat::Bgrx8888 => dest.copy_from_slice(&[0, r, g, b]),
        }
    }
    pub fn rect(&mut self, x: i32, y: i32, w: i32, h: i32, color: u32) {
        if w <= 0 || h <= 0 { return; }
        let x0 = (x as i64).max(0).min(self.surface.width as i64) as usize;
        let y0 = (y as i64).max(0).min(self.surface.height as i64) as usize;
        let x1 = ((x as i64) + (w as i64)).max(0).min(self.surface.width as i64) as usize;
        let y1 = ((y as i64) + (h as i64)).max(0).min(self.surface.height as i64) as usize;
        for py in y0..y1 {
            for px in x0..x1 { self.pixel(px as i32, py as i32, color); }
        }
    }
    pub fn glyph(&mut self, x: i32, y: i32, c: char, color: u32) {
        // Deterministic 5x7 ASCII bitmap fallback; unsupported Unicode -> '?'.
        let rows = glyph_rows(c);
        for (dy, bits) in rows.iter().enumerate() {
            for dx in 0..5 {
                if bits & (1 << (4 - dx)) != 0 { self.pixel(x.saturating_add(dx), y.saturating_add(dy as i32), color); }
            }
        }
    }
    pub fn text(&mut self, x: i32, y: i32, text: &str, color: u32) {
        let mut cx = x;
        for c in text.chars().take(MAX_TEXT) {
            self.glyph(cx, y, c, color);
            cx = cx.saturating_add(6);
        }
    }
}

fn glyph_rows(c: char) -> [u8; 7] {
    // Small built-in font; deliberately no font file or heap allocation.
    match c.to_ascii_uppercase() {
        'A' => [14,17,17,31,17,17,17], 'B' => [30,17,17,30,17,17,30],
        'C' => [15,16,16,16,16,16,15], 'D' => [30,17,17,17,17,17,30],
        'E' => [31,16,16,30,16,16,31], 'F' => [31,16,16,30,16,16,16],
        'G' => [15,16,16,23,17,17,15], 'H' => [17,17,17,31,17,17,17],
        'I' => [31,4,4,4,4,4,31], 'J' => [7,2,2,2,18,18,12],
        'K' => [17,18,20,24,20,18,17], 'L' => [16,16,16,16,16,16,31],
        'M' => [17,27,21,21,17,17,17], 'N' => [17,25,21,19,17,17,17],
        'O' => [14,17,17,17,17,17,14], 'P' => [30,17,17,30,16,16,16],
        'Q' => [14,17,17,17,21,18,13], 'R' => [30,17,17,30,20,18,17],
        'S' => [15,16,16,14,1,1,30], 'T' => [31,4,4,4,4,4,4],
        'U' => [17,17,17,17,17,17,14], 'V' => [17,17,17,17,17,10,4],
        'W' => [17,17,17,21,21,21,10], 'X' => [17,17,10,4,10,17,17],
        'Y' => [17,17,10,4,4,4,4], 'Z' => [31,1,2,4,8,16,31],
        '0' => [14,17,19,21,25,17,14], '1' => [4,12,4,4,4,4,14],
        '2' => [14,17,1,2,4,8,31], '3' => [30,1,1,14,1,1,30],
        '4' => [2,6,10,18,31,2,2], '5' => [31,16,16,30,1,1,30],
        '6' => [14,16,16,30,17,17,14], '7' => [31,1,2,4,8,8,8],
        '8' => [14,17,17,14,17,17,14], '9' => [14,17,17,15,1,1,14],
        ' ' => [0;7], '.' => [0,0,0,0,0,12,12], ':' => [0,12,12,0,12,12,0],
        '-' => [0,0,0,31,0,0,0], '_' => [0,0,0,0,0,0,31],
        '/' => [1,2,2,4,8,8,16], '>' => [16,8,4,2,4,8,16],
        _ => [14,17,1,2,4,0,4],
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    PointerMove { x: i32, y: i32 },
    PointerDown, PointerUp,
    Text(char), Backspace, Tab,
}

#[derive(Clone, Copy)]
pub struct Window {
    pub x: i32, pub y: i32, pub width: i32, pub height: i32,
    pub open: bool, pub title: &'static str,
    pub text: [u8; MAX_TEXT], pub text_len: usize,
}
impl Window {
    const fn new(x: i32, y: i32, title: &'static str) -> Self {
        Self { x, y, width: 260, height: 154, open: true, title,
            text: [0; MAX_TEXT], text_len: 0 }
    }
    pub fn input(&self) -> &str {
        core::str::from_utf8(&self.text[..self.text_len]).unwrap_or("")
    }
    fn append(&mut self, c: char) {
        if !c.is_ascii() || c.is_ascii_control() { return; }
        if self.text_len < MAX_TEXT {
            self.text[self.text_len] = c as u8;
            self.text_len += 1;
        }
    }
}
pub trait DisplayBackend {
    type Error;
    /// Backend must validate its own lifecycle; it cannot assume GPU ownership.
    fn present(&mut self, surface: Surface, bytes: &[u8]) -> Result<(), Self::Error>;
}
pub trait InputBackend {
    fn next_event(&mut self) -> Option<Event>;
}

pub struct Desktop {
    pub windows: [Window; 2],
    pub pointer: (i32, i32),
    pub focused: Option<usize>,
    drag: Option<(usize, i32, i32)>,
    pressed: bool,
}
impl Default for Desktop {
    fn default() -> Self { Self::new() }
}
impl Desktop {
    pub const fn new() -> Self {
        Self { windows: [
            Window::new(56, 62, "CONSOLE"),
            Window::new(164, 120, "NOTES"),
        ], pointer: (24, 24), focused: Some(1), drag: None, pressed: false }
    }
    fn hit(&self, x: i32, y: i32) -> Option<usize> {
        // Focused window is topmost.
        let order = if self.focused == Some(0) { [0, 1] } else { [1, 0] };
        order.into_iter().find(|&i| {
            let w = &self.windows[i];
            w.open && (x as i64) >= w.x as i64 && (y as i64) >= w.y as i64 &&
                (x as i64) < w.x as i64 + w.width as i64 &&
                (y as i64) < w.y as i64 + w.height as i64
        })
    }
    pub fn event(&mut self, event: Event) {
        match event {
            Event::PointerMove { x, y } => {
                self.pointer = (x, y);
                if self.pressed {
                    if let Some((i, ox, oy)) = self.drag {
                        self.windows[i].x = x.saturating_sub(ox);
                        self.windows[i].y = y.saturating_sub(oy);
                    }
                }
            }
            Event::PointerDown => {
                self.pressed = true;
                self.drag = None;
                self.focused = self.hit(self.pointer.0, self.pointer.1);
                if let Some(i) = self.focused {
                    let w = &mut self.windows[i];
                    let rx = self.pointer.0 as i64 - w.x as i64;
                    let ry = self.pointer.1 as i64 - w.y as i64;
                    if ry >= 0 && ry < 24 {
                        if rx >= w.width as i64 - 24 {
                            w.open = false;
                            self.focused = self.windows.iter().position(|w| w.open);
                        } else {
                            self.drag = Some((i, rx as i32, ry as i32));
                        }
                    }
                }
            }
            Event::PointerUp => { self.pressed = false; self.drag = None; }
            Event::Tab => {
                self.focused = match self.focused {
                    Some(0) if self.windows[1].open => Some(1),
                    Some(1) if self.windows[0].open => Some(0),
                    _ => self.windows.iter().position(|w| w.open)
                };
            }
            Event::Text(c) => {
                if let Some(i) = self.focused {
                    if self.windows[i].open { self.windows[i].append(c); }
                }
            }
            Event::Backspace => {
                if let Some(i) = self.focused {
                    let w = &mut self.windows[i];
                    if w.open && w.text_len > 0 { w.text_len -= 1; w.text[w.text_len] = 0; }
                }
            }
        }
    }
    /// A bounded drain prevents an untrusted producer starving frame presentation.
    /// Additional events remain in the backend for the next frame.
    pub fn pump<I: InputBackend>(&mut self, input: &mut I) -> usize {
        let mut n = 0;
        while n < MAX_EVENTS_PER_FRAME {
            let Some(event) = input.next_event() else { break };
            self.event(event);
            n += 1;
        }
        n
    }
    pub fn render(&self, frame: &mut Frame<'_>) {
        frame.clear(0x172337);
        frame.rect(0, 0, frame.surface.width as i32, 31, 0x273b55);
        frame.text(12, 11, "FORTRESS OS  /  EXPERIMENTAL GUI", 0xf7f7f7);
        let back = if self.focused == Some(0) { [1, 0] } else { [0, 1] };
        for i in back {
            let w = &self.windows[i];
            if !w.open { continue; }
            frame.rect(w.x.saturating_add(4), w.y.saturating_add(5), w.width, w.height, 0x0b1220);
            frame.rect(w.x, w.y, w.width, w.height, 0xe7edf5);
            frame.rect(w.x, w.y, w.width, 24,
                if self.focused == Some(i) { 0x396daa } else { 0x52647a });
            frame.text(w.x.saturating_add(9), w.y.saturating_add(8), w.title, 0xffffff);
            frame.rect(w.x.saturating_add(w.width).saturating_sub(23), w.y.saturating_add(3), 20, 18, 0x9c3e45);
            frame.text(w.x.saturating_add(w.width).saturating_sub(16), w.y.saturating_add(9), "X", 0xffffff);
            frame.rect(w.x.saturating_add(12), w.y.saturating_add(42), w.width.saturating_sub(24), 31, 0xffffff);
            frame.text(w.x.saturating_add(18), w.y.saturating_add(53), w.input(), 0x101d30);
            frame.text(w.x.saturating_add(12), w.y.saturating_add(92), "CLICK TITLE TO DRAG", 0x40536c);
            frame.text(w.x.saturating_add(12), w.y.saturating_add(108), "TAB TO SWITCH", 0x40536c);
        }
        let (x, y) = self.pointer;
        frame.rect(x, y, 2, 17, 0xffffff);
        frame.rect(x, y, 11, 2, 0xffffff);
        frame.rect(x.saturating_add(2), y.saturating_add(2), 2, 10, 0xffffff);
    }
    pub fn render_and_present<B: DisplayBackend>(
        &self, frame: &mut Frame<'_>, backend: &mut B
    ) -> Result<(), B::Error> {
        self.render(frame);
        backend.present(frame.surface, frame.bytes())
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    const S: Surface = Surface {
        width: 640, height: 480, stride: 640 * 4, format: PixelFormat::Xrgb8888
    };
    #[test]
    fn geometry_and_buffer_validation() {
        assert_eq!(Surface { stride: 3, ..S }.required_bytes(), Err(Error::InvalidGeometry));
        assert_eq!(Surface { width: usize::MAX, ..S }.required_bytes(), Err(Error::InvalidGeometry));
        assert_eq!(Surface { height: 0, ..S }.required_bytes(), Err(Error::InvalidGeometry));
        assert_eq!(Surface { stride: usize::MAX, ..S }.required_bytes(), Err(Error::InvalidGeometry));
        let mut short = [0u8; 8];
        assert!(matches!(Frame::new(S, &mut short), Err(Error::BufferTooSmall)));
    }
    #[test]
    fn pixels_stride_clipping_and_format() {
        let s = Surface { width: 2, height: 2, stride: 12, format: PixelFormat::Xrgb8888 };
        let mut data = [0x77u8; 24];
        let mut frame = Frame::new(s, &mut data).unwrap();
        frame.rect(-100, -100, 101, 101, 0x123456);
        frame.pixel(i32::MAX, i32::MAX, 0);
        assert_eq!(&frame.bytes()[0..4], &[0x56,0x34,0x12,0]);
        assert_eq!(&frame.bytes()[8..12], &[0x77;4]);
        assert_eq!(&frame.bytes()[12..16], &[0x77;4]);
    }
    #[test]
    fn focus_drag_close_text_and_backspace() {
        let mut desktop = Desktop::new();
        desktop.event(Event::Tab);
        assert_eq!(desktop.focused, Some(0));
        desktop.event(Event::Text('A'));
        desktop.event(Event::Text('é')); // unsupported UTF-8 intentionally dropped, not split
        assert_eq!(desktop.windows[0].input(), "A");
        desktop.event(Event::Backspace);
        assert_eq!(desktop.windows[0].input(), "");
        desktop.event(Event::PointerMove { x: 70, y: 70 });
        desktop.event(Event::PointerDown);
        desktop.event(Event::PointerMove { x: 90, y: 100 });
        desktop.event(Event::PointerUp);
        assert_eq!((desktop.windows[0].x, desktop.windows[0].y), (76, 92));
        desktop.event(Event::PointerMove { x: 76 + 250, y: 98 });
        desktop.event(Event::PointerDown);
        assert!(!desktop.windows[0].open);
        desktop.event(Event::Text('X'));
        assert_eq!(desktop.windows[0].input(), "");
    }
    #[test]
    fn extreme_glyph_coordinates_are_clipped_without_overflow() {
        let mut pixels = vec![0u8; S.required_bytes().unwrap()];
        let mut frame = Frame::new(S, &mut pixels).unwrap();
        for coordinate in [i32::MIN, i32::MIN + 2, i32::MAX - 2, i32::MAX] {
            frame.glyph(coordinate, coordinate, 'A', 0xffffff);
            frame.text(coordinate, coordinate, "TEST", 0xffffff);
        }
        assert!(frame.bytes().iter().all(|&byte| byte == 0));
    }
    #[test]
    fn extreme_pointer_and_drag_events_render_without_overflow() {
        let mut pixels = vec![0u8; S.required_bytes().unwrap()];
        let mut frame = Frame::new(S, &mut pixels).unwrap();
        let mut desktop = Desktop::new();
        for coordinate in [i32::MIN, i32::MAX] {
            desktop.event(Event::PointerMove { x: coordinate, y: coordinate });
            desktop.render(&mut frame);
        }
        // Start dragging a real title bar before receiving extreme input.
        desktop.event(Event::PointerMove { x: 70, y: 70 });
        desktop.event(Event::PointerDown);
        for coordinate in [i32::MAX, i32::MIN] {
            desktop.event(Event::PointerMove { x: coordinate, y: coordinate });
            desktop.render(&mut frame);
        }
        desktop.event(Event::PointerUp);
        desktop.event(Event::PointerMove { x: 24, y: 24 });
        desktop.event(Event::Text('A'));
        desktop.render(&mut frame);
        assert_eq!(desktop.windows[0].input(), "A");
    }
    struct Flood { remaining: usize }
    impl InputBackend for Flood {
        fn next_event(&mut self) -> Option<Event> {
            if self.remaining == 0 { None } else {
                self.remaining -= 1; Some(Event::Text('a'))
            }
        }
    }
    #[test]
    fn bounded_event_flood() {
        let mut desktop = Desktop::new();
        let mut input = Flood { remaining: 1000 };
        assert_eq!(desktop.pump(&mut input), MAX_EVENTS_PER_FRAME);
        assert_eq!(input.remaining, 1000 - MAX_EVENTS_PER_FRAME);
        assert_eq!(desktop.windows[1].text_len, MAX_TEXT);
    }
    struct Sink { count: usize }
    impl DisplayBackend for Sink {
        type Error = ();
        fn present(&mut self, s: Surface, bytes: &[u8]) -> Result<(), ()> {
            assert_eq!(bytes.len(), s.required_bytes().unwrap());
            self.count += 1;
            Ok(())
        }
    }
    #[test]
    fn deterministic_frames_and_present() {
        let mut pixels = vec![0u8; S.required_bytes().unwrap()];
        let mut frame = Frame::new(S, &mut pixels).unwrap();
        let desktop = Desktop::new();
        let mut sink = Sink { count: 0 };
        desktop.render_and_present(&mut frame, &mut sink).unwrap();
        let first = frame.bytes().to_vec();
        desktop.render_and_present(&mut frame, &mut sink).unwrap();
        assert_eq!(first, frame.bytes());
        assert_eq!(sink.count, 2);
        assert!(first.iter().any(|&b| b != 0));
    }
    struct Failing;
    impl DisplayBackend for Failing {
        type Error = u8;
        fn present(&mut self, _: Surface, _: &[u8]) -> Result<(), u8> { Err(9) }
    }
    #[test]
    fn present_failure_propagated() {
        let mut pixels = vec![0u8; S.required_bytes().unwrap()];
        let mut frame = Frame::new(S, &mut pixels).unwrap();
        assert_eq!(Desktop::new().render_and_present(&mut frame, &mut Failing), Err(9));
    }
}
