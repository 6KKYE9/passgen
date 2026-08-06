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

func TestRemoveChars(t *testing.T) {
	if got := removeChars("abcdef", "bdf"); got != "ace" {
		t.Fatalf("应为 ace，实际 %q", got)
	}
	if got := removeChars("abc", ""); got != "abc" {
		t.Fatalf("drop 为空应原样返回，实际 %q", got)
	}
	if got := removeChars("aaa", "a"); got != "" {
		t.Fatalf("全被剔除应为空串，实际 %q", got)
	}
}

func TestRemoveCharsNoAmbiguous(t *testing.T) {
	cs := removeChars(lower+upper+digits, ambiguous)
	for _, r := range ambiguous {
		if strings.ContainsRune(cs, r) {
			t.Fatalf("剔除后仍含易混淆字符 %q", string(r))
		}
	}
	// 剩下的字符应该还够用，不至于把字母数字挖空。
	if len(cs) < 40 {
		t.Fatalf("剔除易混淆字符后字符集过小：%d", len(cs))
	}
}

func TestFilterClassesDropsEmpty(t *testing.T) {
	classes := []string{lower, digits}
	got := filterClasses(classes, digits)
	if len(got) != 1 {
		t.Fatalf("数字类应被整类剔除，剩余 %d 个类", len(got))
	}
	if got[0] != lower {
		t.Fatalf("剩下的应是小写类，实际 %q", got[0])
	}
}

func TestGenerateGuaranteedWithExclusion(t *testing.T) {
	drop := ambiguous + "@#"
	charset := removeChars(lower+upper+digits+symbols, drop)
	classes := filterClasses([]string{lower, upper, digits, symbols}, drop)
	for i := 0; i < 100; i++ {
		pw := generateGuaranteed(16, charset, classes)
		for _, r := range pw {
			if strings.ContainsRune(drop, r) {
				t.Fatalf("密码 %q 含被排除字符 %q", pw, string(r))
			}
		}
	}
}

func TestGenerateWords(t *testing.T) {
	if got := generateWords(0, "-"); got != "" {
		t.Fatalf("0 个词应为空串，实际 %q", got)
	}
	for i := 0; i < 50; i++ {
		pw := generateWords(4, "-")
		parts := strings.Split(pw, "-")
		// 4 个词 + 末尾两位数字 = 5 段
		if len(parts) != 5 {
			t.Fatalf("应为 5 段，实际 %d：%q", len(parts), pw)
		}
		for _, w := range parts[:4] {
			found := false
			for _, cand := range wordList {
				if cand == w {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%q 不在词表里", w)
			}
		}
		if len(parts[4]) != 2 {
			t.Fatalf("末尾应为两位数字，实际 %q", parts[4])
		}
	}
}

func TestGenerateWordsCustomSep(t *testing.T) {
	pw := generateWords(3, ".")
	if strings.Count(pw, ".") != 3 {
		t.Fatalf("3 个词应有 3 个分隔符，实际 %q", pw)
	}
}

func TestWordsEntropyBits(t *testing.T) {
	if wordsEntropyBits(0) != 0 {
		t.Fatalf("0 个词熵应为 0")
	}
	want := 4*math.Log2(float64(len(wordList))) + math.Log2(100)
	if got := wordsEntropyBits(4); math.Abs(got-want) > 0.001 {
		t.Fatalf("应为 %.3f，实际 %.3f", want, got)
	}
}

func TestBitsLabel(t *testing.T) {
	cases := []struct {
		bits float64
		want string
	}{
		{100, "强"},
		{60, "强"},
		{59.9, "中"},
		{36, "中"},
		{35.9, "弱"},
		{0, "弱"},
	}
	for _, c := range cases {
		if got := bitsLabel(c.bits); got != c.want {
			t.Fatalf("bitsLabel(%.1f) 应为 %s，实际 %s", c.bits, c.want, got)
		}
	}
}
