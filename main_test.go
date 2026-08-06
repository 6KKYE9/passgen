package main

import (
	"math"
	"strings"
	"testing"
)

func TestGenerateLength(t *testing.T) {
	cs := lower + upper + digits + symbols
	for _, n := range []int{1, 8, 16, 64} {
		got := generate(n, cs)
		if len(got) != n {
			t.Fatalf("generate(%d) 长度应为 %d，实际 %d", n, n, len(got))
		}
	}
	if got := generate(0, cs); got != "" {
		t.Fatalf("generate(0) 应为空串，实际 %q", got)
	}
}

func TestGenerateUsesCharset(t *testing.T) {
	cs := digits
	for i := 0; i < 50; i++ {
		got := generate(20, cs)
		for _, r := range got {
			if !strings.ContainsRune(cs, r) {
				t.Fatalf("generate 出现了字符集外的字符 %q", string(r))
			}
		}
	}
}

func TestGenerateGuaranteedHasEveryClass(t *testing.T) {
	charset := lower + upper + digits + symbols
	classes := []string{lower, upper, digits, symbols}
	for i := 0; i < 100; i++ {
		pw := generateGuaranteed(16, charset, classes)
		if len(pw) != 16 {
			t.Fatalf("长度应为 16，实际 %d", len(pw))
		}
		for _, c := range classes {
			if !strings.ContainsAny(pw, c) {
				t.Fatalf("生成的密码 %q 缺少字符类 %q", pw, c)
			}
		}
	}
}

func TestGenerateGuaranteedShort(t *testing.T) {
	// 长度小于类数时退化为普通生成，不 panic。
	charset := lower + upper + digits + symbols
	classes := []string{lower, upper, digits, symbols}
	if got := generateGuaranteed(2, charset, classes); len(got) != 2 {
		t.Fatalf("短密码长度应为 2，实际 %d", len(got))
	}
}

func TestEntropyBits(t *testing.T) {
	// 16 位、62 字符集 ≈ 95.3 bits
	got := entropyBits(strings.Repeat("a", 16), lower+upper+digits)
	want := 16 * math.Log2(62)
	if math.Abs(got-want) > 0.001 {
		t.Fatalf("entropyBits 应为 %.3f，实际 %.3f", want, got)
	}
	if entropyBits("x", "") != 0 {
		t.Fatalf("空字符集熵应为 0")
	}
}

func TestStrength(t *testing.T) {
	// 16 位 62 字符集 -> 强
	if s := strength(strings.Repeat("a", 16), lower+upper+digits); s != "强" {
		t.Fatalf("16 位 62 集应为 强，实际 %s", s)
	}
	// 4 位只数字 -> 弱
	if s := strength("1234", digits); s != "弱" {
		t.Fatalf("4 位数字应为 弱，实际 %s", s)
	}
	// 12 位数字 ≈ 39.9 bits -> 中
	if s := strength(strings.Repeat("1", 12), digits); s != "中" {
		t.Fatalf("12 位数字应为 中，实际 %s", s)
	}
}

func TestBuildCharset(t *testing.T) {
	if got := buildCharset(false, false, false, false); got != "" {
		t.Fatalf("全关应为空，实际 %q", got)
	}
	if got := buildCharset(true, true, true, false); got != lower+upper+digits {
		t.Fatalf("不含符号应为 %q，实际 %q", lower+upper+digits, got)
	}
}
