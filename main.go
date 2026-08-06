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
//   passgen -no-ambiguous   # 去掉 0O1lI 这类肉眼容易看错的字符
//   passgen -exclude "@#$"  # 手动排除某些字符（有些系统不接受）
//   passgen -words 4        # 生成 4 个词拼起来的易记口令
//   passgen -quiet          # 只打印密码本身，方便管道
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"
)

const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "!@#$%^&*()-_=+[]{};:,.<>?"

	// 这些字符在常见字体里长得太像，抄写密码时最容易出错。
	ambiguous = "0Oo1lI|`'\";:,."
)

// wordList 是口令模式用的词表。词都短、好念、无歧义，拼起来比乱码好记得多。
var wordList = []string{
	"apple", "beach", "cloud", "delta", "eagle", "flame", "grape", "honey",
	"ivory", "jelly", "koala", "lemon", "mango", "noble", "ocean", "piano",
	"quilt", "river", "stone", "tiger", "umbra", "vivid", "whale", "xenon",
	"yacht", "zebra", "amber", "brick", "candy", "drift", "ember", "frost",
}

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

// removeChars 从 s 里剔除 drop 中出现过的所有字符，返回剩下的部分。
// 用来实现 -exclude 和 -no-ambiguous：先拼好全集，再把不想要的挖掉。
func removeChars(s, drop string) string {
	if drop == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(drop, rune(s[i])) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// filterClasses 对每个字符类做同样的剔除，并丢掉被剔空的类。
// 不丢掉空类的话，generateGuaranteed 会对空字符串取下标而 panic。
func filterClasses(classes []string, drop string) []string {
	out := make([]string, 0, len(classes))
	for _, c := range classes {
		if f := removeChars(c, drop); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// generateWords 从词表里随机挑 n 个词，用 sep 连起来，末尾补两位数字。
// 这类口令熵不如乱码高，但胜在能背下来，适合当主密码。
func generateWords(n int, sep string) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, wordList[randomIndex(len(wordList))])
	}
	// 补两位数字，绕开"必须含数字"这类常见密码策略。
	return strings.Join(parts, sep) + sep + fmt.Sprintf("%02d", randomIndex(100))
}

// wordsEntropyBits 估算口令模式的熵：每个词贡献 log2(词表大小)，末尾数字贡献 log2(100)。
func wordsEntropyBits(n int) float64 {
	if n <= 0 {
		return 0
	}
	return float64(n)*math.Log2(float64(len(wordList))) + math.Log2(100)
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

// bitsLabel 把熵位数翻成"强/中/弱"三档，方便一眼看懂。
func bitsLabel(bits float64) string {
	switch {
	case bits >= 60:
		return "强"
	case bits >= 36:
		return "中"
	default:
		return "弱"
	}
}

// strength 给密码估个粗略强度（按真实熵位估算，仅供直观参考，不是严谨评分）。
func strength(pw string, charset string) string {
	return bitsLabel(entropyBits(pw, charset))
}

func main() {
	lenFlag := flag.Int("len", 16, "密码长度")
	count := flag.Int("count", 1, "一次生成几条")
	useSymbols := flag.Bool("symbols", true, "是否包含符号（默认包含）")
	noSymbols := flag.Bool("no-symbols", false, "不包含符号（与 -symbols=false 等价）")
	noUpper := flag.Bool("no-upper", false, "不包含大写字母")
	noDigits := flag.Bool("no-digits", false, "不包含数字")
	onlyDigits := flag.Bool("only-digits", false, "只生成数字（如验证码）")
	noAmbiguous := flag.Bool("no-ambiguous", false, "去掉 0O1lI 这类容易看错的字符")
	exclude := flag.String("exclude", "", "额外排除的字符，比如 -exclude \"@#$\"")
	words := flag.Int("words", 0, "改用口令模式，生成 N 个单词拼成的易记口令")
	sep := flag.String("sep", "-", "口令模式的单词分隔符")
	quiet := flag.Bool("quiet", false, "只输出密码，不打印强度信息")
	flag.Parse()

	// 口令模式和字符模式是两条路，先处理口令模式再返回。
	if *words > 0 {
		bits := wordsEntropyBits(*words)
		for i := 0; i < *count; i++ {
			pw := generateWords(*words, *sep)
			if *quiet {
				fmt.Println(pw)
			} else {
				fmt.Printf("%s  [%s, %.1f bits]\n", pw, bitsLabel(bits), bits)
			}
		}
		return
	}

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
		useDigits := !*noDigits
		charset = buildCharset(useUpper, true, useDigits, symbolsOn)
		classes = []string{lower}
		if useUpper {
			classes = append(classes, upper)
		}
		if useDigits {
			classes = append(classes, digits)
		}
		if symbolsOn {
			classes = append(classes, symbols)
		}
	}

	// 两种排除叠加：先算出要挖掉的字符，再从全集和每个类里同时挖。
	drop := *exclude
	if *noAmbiguous {
		drop += ambiguous
	}
	charset = removeChars(charset, drop)
	classes = filterClasses(classes, drop)

	if len(charset) == 0 {
		fmt.Fprintln(os.Stderr, "字符集为空，请检查参数")
		os.Exit(1)
	}

	for i := 0; i < *count; i++ {
		pw := generateGuaranteed(*lenFlag, charset, classes)
		if *quiet {
			fmt.Println(pw)
			continue
		}
		fmt.Printf("%s  [%s, %.1f bits]\n", pw, strength(pw, charset), entropyBits(pw, charset))
	}
}
