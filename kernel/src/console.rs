//! Bounded ASCII line discipline for the diagnostic serial console.

const MAX_LINE: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum LineResult {
    Empty,
    Invalid,
    Unknown,
    Help,
    Status,
    Version,
    Exit,
    Calculation(i64),
    InvalidCalculation,
    DivisionByZero,
    ArithmeticOverflow,
}

pub struct LineEditor {
    buffer: [u8; MAX_LINE],
    length: usize,
    invalid: bool,
    after_cr: bool,
}

impl LineEditor {
    pub const fn new() -> Self {
        Self {
            buffer: [0; MAX_LINE],
            length: 0,
            invalid: false,
            after_cr: false,
        }
    }

    /// Treat a reported UART error as a corrupt byte in the current line.
    pub fn invalidate(&mut self) {
        self.invalid = true;
        self.after_cr = false;
    }

    /// Return a result only after a complete line. CRLF terminates one line.
    pub fn feed(&mut self, byte: u8) -> Option<LineResult> {
        let after_cr = self.after_cr;
        self.after_cr = byte == b'\r';
        match byte {
            b'\n' if after_cr => None,
            b'\r' | b'\n' => Some(self.finish_line()),
            _ if self.invalid => None,
            0x08 | 0x7f => {
                self.length = self.length.saturating_sub(1);
                None
            }
            b' '..=b'~' if self.length < MAX_LINE => {
                self.buffer[self.length] = byte;
                self.length += 1;
                None
            }
            _ => {
                self.invalidate();
                None
            }
        }
    }

    fn finish_line(&mut self) -> LineResult {
        let result = if self.invalid {
            LineResult::Invalid
        } else {
            match &self.buffer[..self.length] {
                b"" => LineResult::Empty,
                b"help" => LineResult::Help,
                b"status" => LineResult::Status,
                b"version" => LineResult::Version,
                b"exit" => LineResult::Exit,
                b"calc" => LineResult::InvalidCalculation,
                command => match command.strip_prefix(b"calc ") {
                    Some(expression) => calculate(expression),
                    None => LineResult::Unknown,
                },
            }
        };
        self.length = 0;
        self.invalid = false;
        result
    }
}

fn operand(input: &[u8]) -> Option<(&str, &[u8])> {
    let input = input.trim_ascii_start();
    let sign = usize::from(matches!(input.first(), Some(b'+' | b'-')));
    let digits = input[sign..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits == 0 {
        return None;
    }
    let (number, remaining) = input.split_at(sign + digits);
    Some((core::str::from_utf8(number).ok()?, remaining.trim_ascii_start()))
}

fn calculate(expression: &[u8]) -> LineResult {
    use LineResult::*;

    let Some((lhs, rest)) = operand(expression) else {
        return InvalidCalculation;
    };
    let Some((op @ (b'+' | b'-' | b'*' | b'/' | b'%'), rest)) = rest.split_first() else {
        return InvalidCalculation;
    };
    let Some((rhs, b"")) = operand(rest) else {
        return InvalidCalculation;
    };
    // Syntax is validated first, so out-of-range literals differ from junk.
    let (Ok(lhs), Ok(rhs)) = (lhs.parse::<i64>(), rhs.parse::<i64>()) else {
        return ArithmeticOverflow;
    };
    if rhs == 0 && matches!(op, b'/' | b'%') {
        return DivisionByZero;
    }
    let value = match op {
        b'+' => lhs.checked_add(rhs),
        b'-' => lhs.checked_sub(rhs),
        b'*' => lhs.checked_mul(rhs),
        b'/' => lhs.checked_div(rhs),
        // Like checked_div, checked_rem rejects i64::MIN with divisor -1.
        b'%' => lhs.checked_rem(rhs),
        _ => return InvalidCalculation,
    };
    value.map_or(ArithmeticOverflow, Calculation)
}

#[cfg(test)]
mod tests {
    use super::{LineEditor, LineResult, MAX_LINE};
    use LineResult::*;

    fn enter(editor: &mut LineEditor, line: &[u8], expected: LineResult) {
        for &byte in line {
            assert_eq!(editor.feed(byte), None);
        }
        assert_eq!(editor.feed(b'\n'), Some(expected));
    }

    #[test]
    fn accepts_only_exact_complete_commands() {
        let mut editor = LineEditor::new();
        enter(&mut editor, b"help", Help);
        enter(&mut editor, b"status", Status);
        enter(&mut editor, b"version", Version);
        enter(&mut editor, b"exit", Exit);
        for line in [b" help".as_slice(), b"HELP", b"help ", b"status exit", b"ex"] {
            enter(&mut editor, line, Unknown);
        }
    }

    #[test]
    fn crlf_is_one_terminator_and_empty_lines_are_harmless() {
        let mut editor = LineEditor::new();
        for &byte in b"help" {
            assert_eq!(editor.feed(byte), None);
        }
        assert_eq!(editor.feed(b'\r'), Some(Help));
        assert_eq!(editor.feed(b'\n'), None);
        assert_eq!(editor.feed(b'\r'), Some(Empty));
        assert_eq!(editor.feed(b'\r'), Some(Empty));
        assert_eq!(editor.feed(b'\n'), None);
        assert_eq!(editor.feed(b'\n'), Some(Empty));
    }

    #[test]
    fn handles_backspace_and_delete_at_both_ends() {
        let mut editor = LineEditor::new();
        enter(&mut editor, b"\x08\x7fheX\x08lpX\x7f", Help);
        enter(&mut editor, b"x\x08\x08", Empty);
    }

    #[test]
    fn rejects_invalid_bytes_and_ansi_sequences_for_the_entire_line() {
        let mut editor = LineEditor::new();
        for line in [
            b"\x1b[Aexit".as_slice(),
            b"exit\0",
            b"\x80help",
            b"ver\t\x08sion",
        ] {
            enter(&mut editor, line, Invalid);
            enter(&mut editor, b"status", Status);
        }
    }

    #[test]
    fn overflow_cannot_execute_a_prefix_or_be_undone_by_backspace() {
        let mut editor = LineEditor::new();
        let mut line = [b'x'; MAX_LINE];
        line[..4].copy_from_slice(b"exit");
        enter(&mut editor, &line, Unknown);
        for byte in line {
            assert_eq!(editor.feed(byte), None);
        }
        assert_eq!(editor.feed(b'x'), None);
        for _ in 4..=MAX_LINE {
            assert_eq!(editor.feed(0x08), None);
        }
        assert_eq!(editor.feed(b'\r'), Some(Invalid));
        assert_eq!(editor.feed(b'\n'), None);
        enter(&mut editor, b"help", Help);
    }

    #[test]
    fn calculates_one_operator_with_signed_i64_operands() {
        let mut editor = LineEditor::new();
        for (line, value) in [
            (b"calc 2+3".as_slice(), 5),
            (b"calc +2 - -3", 5),
            (b"calc -2*-3", 6),
            (b"calc  -7 / 3 ", -2),
            (b"calc -7 % 3", -1),
            (b"calc -9223372036854775808+0", i64::MIN),
            (b"calc 9223372036854775807+0", i64::MAX),
        ] {
            enter(&mut editor, line, Calculation(value));
        }
    }

    #[test]
    fn reports_zero_divisors_and_overflow_separately() {
        let mut editor = LineEditor::new();
        for line in [b"calc 1/0".as_slice(), b"calc -1%-0"] {
            enter(&mut editor, line, DivisionByZero);
        }
        for line in [
            b"calc 9223372036854775807+1".as_slice(),
            b"calc -9223372036854775808-1",
            b"calc 9223372036854775807*2",
            b"calc -9223372036854775808/-1",
            b"calc -9223372036854775808%-1",
            b"calc 9223372036854775808+0",
            b"calc 0+-9223372036854775809",
        ] {
            enter(&mut editor, line, ArithmeticOverflow);
        }
        enter(&mut editor, b"calc 12*3", Calculation(36));
    }

    #[test]
    fn rejects_malformed_calculations_without_consuming_the_next_line() {
        let mut editor = LineEditor::new();
        for line in [
            b"calc".as_slice(),
            b"calc  ",
            b"calc 1+",
            b"calc --1+2",
            b"calc (1+2)",
            b"calc 1^2",
            b"calc 1+2*3",
            b"calc 1+2 exit",
            b"calc 9223372036854775808junk+0",
        ] {
            enter(&mut editor, line, InvalidCalculation);
        }
        enter(&mut editor, b"calc 1+2\x1b", Invalid);
        enter(&mut editor, b"calc 1+2", Calculation(3));
        enter(&mut editor, b"help", Help);
    }

    #[test]
    fn uart_corruption_breaks_crlf_and_poisons_the_next_line() {
        let mut editor = LineEditor::new();
        assert_eq!(editor.feed(b'\r'), Some(Empty));
        editor.invalidate();
        assert_eq!(editor.feed(b'\n'), Some(Invalid));
        for &byte in b"exit" {
            assert_eq!(editor.feed(byte), None);
        }
        editor.invalidate();
        assert_eq!(editor.feed(b'\n'), Some(Invalid));
        enter(&mut editor, b"status", Status);
    }
}
