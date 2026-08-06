// passgen：一个用标准库写的随机密码/口令生成器
//
// 为什么不用 math/rand？因为 math/rand 只是"伪随机"，可被预测，不适合做密码。
// 真正安全的随机来自 crypto/rand（系统提供的加密级随机数）。本示例带你用它对字符集取随机下标。
//
// 用法：
//   passgen                 # 默认生成 1 条 16 位、含大小写+数字+符号 的密码
//   passgen -len 24 -count 5
//   passgen -no-symbols     # 只要字母和数字
//   passgen -only-digits    # 只要数字（比如验证码）
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
)

const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "!@#$%^&*()-_=+[]{};:,.<>?"
)

// randomIndex 用 crypto/rand 在 [0, n) 里取一个不可预测的随机下标。
// 关键：big.Int 的 rand.Int 是从系统熵池取数，比 rand.Intn 安全得多。
func randomIndex(n int) int {
	// rand.Int 返回 [0, max) 的随机大整数；max 是开区间上界，所以传 n。
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		// 几乎不会发生（除非系统随机数源故障），直接退出比返回弱随机更安全。
		fmt.Fprintln(os.Stderr, "随机数生成失败:", err)
		os.Exit(1)
	}
	return int(v.Int64())
}

// buildCharset 根据开关拼出"允许出现的字符集合"。
func buildCharset(useUpper, useLower, useDigits, useSymbols bool) string {
	cs := ""
	if useLower {
		cs += lower
	}
	if useUpper {
		cs += upper
	}
	if useDigits {
		cs += digits
	}
	if useSymbols {
		cs += symbols
	}
	return cs
}

// generate 生成一条指定长度、从给定字符集里取字符的密码。
func generate(length int, charset string) string {
	if length <= 0 {
		return ""
	}
	out := make([]byte, length)
	// 保证每个位置都是独立随机选取。
	for i := 0; i < length; i++ {
		out[i] = charset[randomIndex(len(charset))]
	}
	return string(out)
}

// generateGuaranteed 生成一条密码，并保证其中包含每一个"字符类"至少 1 个字符。
// classes 是各个字符类的字符集合（如小写、大写、数字、符号），charset 是它们拼起来的全集。
// 做法：先从每个类里随机取一个放进前 len(classes) 位，其余位置从全集中随机取，
// 最后把整串打乱，保证"每类至少出现一次"又不暴露哪几位是从特定类取的。
func generateGuaranteed(length int, charset string, classes []string) string {
	if length <= 0 {
		return ""
	}
	if length < len(classes) {
		// 长度不够放下所有类，退化为普通随机生成（少数字符类场景）。
		return generate(length, charset)
	}
	out := make([]byte, 0, length)
	for _, c := range classes {
		out = append(out, c[randomIndex(len(c))])
	}
	for len(out) < length {
		out = append(out, charset[randomIndex(len(charset))])
	}
	// Fisher–Yates 原地打乱，使用 crypto/rand 取交换下标。
	for i := len(out) - 1; i > 0; i-- {
		j := randomIndex(i + 1)
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// entropyBits 估算密码的信息熵（位）：长度 × log2(字符集大小)。
// 这才是"真实强度"的近似——比如 16 位、62 个字符集 ≈ 95.3 位。
func entropyBits(pw, charset string) float64 {
	if len(charset) <= 1 {
		return 0
	}
	return float64(len(pw)) * math.Log2(float64(len(charset)))
}

// strength 给密码估个粗略强度（按真实熵位估算，仅供直观参考，不是严谨评分）。
func strength(pw string, charset string) string {
	bits := entropyBits(pw, charset)
	switch {
	case bits >= 60:
		return "强"
	case bits >= 36:
		return "中"
	default:
		return "弱"
	}
}

func main() {
	lenFlag := flag.Int("len", 16, "密码长度")
	count := flag.Int("count", 1, "一次生成几条")
	useSymbols := flag.Bool("symbols", true, "是否包含符号（默认包含）")
	noSymbols := flag.Bool("no-symbols", false, "不包含符号（与 -symbols=false 等价）")
	noUpper := flag.Bool("no-upper", false, "不包含大写字母")
	onlyDigits := flag.Bool("only-digits", false, "只生成数字（如验证码）")
	flag.Parse()

	// -no-symbols 是 -symbols=false 的便捷写法，二者取"不要符号"的语义。
	symbolsOn := *useSymbols && !*noSymbols

	// 处理"只要数字"这个快捷开关。
	var charset string
	var classes []string // 需要"每类至少出现一次"的字符类
	if *onlyDigits {
		charset = digits
		classes = []string{digits}
	} else {
		useUpper := !*noUpper
		charset = buildCharset(useUpper, true, true, symbolsOn)
		classes = []string{lower, digits}
		if useUpper {
			classes = append(classes, upper)
		}
		if symbolsOn {
			classes = append(classes, symbols)
		}
	}

	if len(charset) == 0 {
		fmt.Fprintln(os.Stderr, "字符集为空，请检查参数")
		os.Exit(1)
	}

	for i := 0; i < *count; i++ {
		pw := generateGuaranteed(*lenFlag, charset, classes)
		fmt.Printf("%s  [%s, %.1f bits]\n", pw, strength(pw, charset), entropyBits(pw, charset))
	}
}
