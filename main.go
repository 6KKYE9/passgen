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

// strength 给密码估个粗略强度（只按长度+字符种类，仅供直观参考，不是严谨评分）。
func strength(pw string, kinds int) string {
	entropy := len(pw) * kinds // 粗略的"可能组合数"对数近似
	switch {
	case entropy >= 60:
		return "强"
	case entropy >= 36:
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
	var kinds int
	if *onlyDigits {
		charset = digits
		kinds = 1
	} else {
		useUpper := !*noUpper
		charset = buildCharset(useUpper, true, true, symbolsOn)
		kinds = 0
		if !*noUpper {
			kinds++
		}
		kinds++ // 小写
		kinds++ // 数字
		if symbolsOn {
			kinds++
		}
	}

	if len(charset) == 0 {
		fmt.Fprintln(os.Stderr, "字符集为空，请检查参数")
		os.Exit(1)
	}

	for i := 0; i < *count; i++ {
		pw := generate(*lenFlag, charset)
		fmt.Printf("%s  [%s]\n", pw, strength(pw, kinds))
	}
}
