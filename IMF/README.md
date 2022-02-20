# IMF

## 实验链接

https://github.com/SoftSec-KAIST/IMF

## patch 作用

当 API 日志中记录的值为 时`'" ' "'`，ApiFuzz 在执行`evaluate`函数时会报错。
因为python将第二个单引号识别为标识符，但这实际上是数据。

为了防止 ApiFuzz 报告错误并让 API Log 更好地显示值字符串，我将所有非字母和非数字字符转义为 '\xXX' 的形式。

而且效果看上去还不错：

```text
{'name':'location','value': '"\x0f\x18"','size' : 0x80,'cnt':0x1, 'data':[]}
```
