# passgen —— 随机密码/口令生成器

一个用 Go 标准库写的命令行小工具，生成**加密级安全**的随机密码或验证码。
不依赖任何第三方库，下载即可用。

## 为什么不用 math/rand

`math/rand` 是伪随机、可被预测，不适合做密码。本工具用 `crypto/rand`
（系统熵池）取随机下标，适合真实场景。

## 编译与运行

```powershell
go run .                 # 默认：1 条 16 位、含大小写+数字+符号
go run . -len 24 -count 5
go run . -no-upper       # 不要大写
go run . -no-symbols     # 不要符号
go run . -only-digits    # 只出数字（验证码）
```

## 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-len` | 16 | 密码长度 |
| `-count` | 1 | 一次生成几条 |
| `-symbols` | true | 是否包含符号 |
| `-no-upper` | false | 不包含大写字母 |
| `-only-digits` | false | 只生成数字 |

## 示例输出

```text
aZ3$kL9@qW2#mN7p  [强]
```

每条后面方括号里是粗略强度估计（按长度和字符种类估算，仅供参考）。

## 文件结构

```
passgen/
├── go.mod    # 模块定义（无任何第三方依赖）
└── main.go   # 全部逻辑：随机取字符 + 强度估计
```

最后更新：2026-08-06
