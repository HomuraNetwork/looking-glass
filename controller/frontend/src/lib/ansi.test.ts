import { describe, expect, it } from "vitest";
import { hasAnsi, parseAnsi, stripAnsi } from "./ansi";

describe("ANSI parser utility", () => {
  it("detects ANSI escape codes", () => {
    expect(hasAnsi("hello world")).toBe(false);
    expect(hasAnsi("\x1b[32mhello\x1b[0m")).toBe(true);
    expect(hasAnsi("\x1b[37;1mNextTrace\x1b[0;22m")).toBe(true);
  });

  it("strips ANSI escape codes cleanly", () => {
    expect(stripAnsi("hello world")).toBe("hello world");
    expect(stripAnsi("\x1b[32mhello\x1b[0m world")).toBe("hello world");
    expect(stripAnsi("\x1b[37;1mNextTrace\x1b[0;22m \x1b[90;1mv1.7.3\x1b[0;22m")).toBe("NextTrace v1.7.3");
  });

  it("strips non-SGR CSI (DEC private) and OSC sequences", () => {
    // nexttrace/--map can toggle the cursor with DEC private sequences; these
    // must be consumed, not leaked as literal "[?25l".
    expect(stripAnsi("\x1b[?25lhello\x1b[?25h")).toBe("hello");
    expect(stripAnsi("a\x1b[?1hb")).toBe("ab");
    expect(stripAnsi("\x1b]0;title\x07text")).toBe("text");
    expect(hasAnsi("\x1b[?25l")).toBe(true);
  });

  it("parses text without ANSI as single span", () => {
    expect(parseAnsi("normal text")).toEqual([{ text: "normal text" }]);
  });

  it("parses standard foreground colors and bold", () => {
    const spans = parseAnsi("\x1b[1;32mGreen Bold\x1b[0m normal");
    expect(spans).toHaveLength(2);
    expect(spans[0].text).toBe("Green Bold");
    expect(spans[0].className).toContain("font-bold");
    expect(spans[0].style?.color).toBe("#4ade80");
    expect(spans[1].text).toBe(" normal");
  });

  it("parses NextTrace style ANSI codes", () => {
    const spans = parseAnsi("\x1b[37;1mNextTrace\x1b[0;22m \x1b[90;1mv1.7.3\x1b[0;22m");
    expect(spans).toHaveLength(3);
    expect(spans[0].text).toBe("NextTrace");
    expect(spans[0].style?.color).toBe("#f1f5f9");
    expect(spans[0].className).toContain("font-bold");
    expect(spans[1].text).toBe(" ");
    expect(spans[2].text).toBe("v1.7.3");
    expect(spans[2].style?.color).toBe("#94a3b8");
  });

  it("parses 256-color and 24-bit truecolor codes", () => {
    const spans256 = parseAnsi("\x1b[38;5;196mRed256\x1b[0m");
    expect(spans256[0].text).toBe("Red256");
    expect(spans256[0].style?.color).toBeDefined();

    const spansRGB = parseAnsi("\x1b[38;2;100;150;200mCustomRGB\x1b[0m");
    expect(spansRGB[0].text).toBe("CustomRGB");
    expect(spansRGB[0].style?.color).toBe("rgb(100, 150, 200)");
  });
});
