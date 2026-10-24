---
title:  "PHPFun: 用 ([.^]) 6種字元寫PHP"
date: 2021-08-04 11:06:21 +0800
tags:
  - Web
  - PHP
categories:
  - Note
---

介紹我魔改的一個小玩具

## Intro

PHPFun是基於[splitline/PHPFuck](https://github.com/splitline/PHPFuck)製作的一個PHP混淆器

PHPFuck使用7種字元來達成，而PHPFun使用6種字元，並用了更多trick來減少字數

(不過因為只用6種字元，所以總字數還是更多一點XD)

## Demo

[Web Interface](https://lebr0nli.github.io/PHPFun/)

[python CLI](https://github.com/lebr0nli/PHPFun)

## How It works?

首先先引用splitline的[文章](https://blog.splitline.tw/2020-06-02/phpfuck)，裡面寫的非常清楚

所以這裡只講和PHPFuck不同的地方

----

- `"ArrayArray"[0]` 與 `"ArrayArray"[1]`

PHPFuck使用`"ArrayArray"[0]`時是以`([].[])[[]^[]]`來達成，但其實可以使用`([].[])[[]]`來達成

原因是php看不懂offset type的時候，會嘗試`(int)`他，而`(int)[]===0`，所以可以直接拿到"A"這個字

同理可以用`([].[])[[[]]]`來得到`"r"`

----

- 產生1234567890的方式

PHPFuck產生>=1的數字是用+的，但由於我沒有使用+號，所以產生方式需要修改

首先是數字3，我們可以透過`"A"^"r"`來產生`"3"`

雖然"3"的型態是`string`，但是不管是與`int`的數字xor或作為某個`string`的index，在php裡面都與`int` 3效果等價，所以不影響使用

因此，當我們得到"3"之後，我們可以直接通過`"3"^[]`來得到`int` 2

類似`"3"`情況的還有`"8"`，我們可以透過`"A"^"y"`來得到`"8"`

但這裡遇到一個問題，`"ArrayArray"`只有index是4或9才有辦法拿到`"y"`

4或9我們目前都沒有，這下該怎麼辦呢？

但沒關係，我們還是有辦法！

我們只需要將`0`與`"ArrayArray"`連接，即可在`["10"]`拿到`"y"`

也就是`(([]^[]).[].[])[([]^[[]]).([]^[])]` !

得到`"8"`之後，我們即可透過`"8"^[]`再得到一個9

有012389後，我們下個目標是4567，我們可以注意到`4===8^12`

這就代表我們能夠產生4了！

具體產生的方式是：

`"8"^[]^((1).(2))`

執得注意的是中間的`^[]^`是必須存在的，因為如果`"8"`沒有先和`[]`做xor來轉換為`int` 8，`"8"^"12"`得到的會是`"\t"`

處理完`4`之後，接下來產生567都很簡單

`5`可以用`4 ^ [[]]`產生

`6`可以用`2 ^ 4`產生

`7`可以用`3 ^ 4`產生

有了`Aray0123456789`之後，如同splitline內文所提，可以暴力xor出所有需要字元，然後任意執行

----

- "1Array" ^ "A" == ?

在上文可以看到`"8"^"12"`這個例子，因為長度不同，最後xor出來的長度跟`"8"`一樣

所以可以利用這個特性，當需要把`int`型的數字toString再與其他單一字元xor時，可以利用`.[]`就行

而不需要如PHPFuck裡面一樣透過`.[][[]]`，也就是與`NULL`連接來toString

## Summary

```php
"ArrayArray" => [].[]
0 => []^[]
1 => []^[[]]
"A" => "ArrayArray"[[]]
"r" => "ArrayArray"[[[]]]
"3" => "A" ^ "r"
2 => "3" ^ [[]]
"y" => "0ArrayArray"[10] => ((0)."ArrayArray")[(1).(0)]
"8" => "A" ^ "y"
4 => "8" ^ [] ^ ((1).(2))
5 => 4 ^ [[]]
6 => 2 ^ 4
7 => 3 ^ 4
9 => "8" ^ [[]]
"p" => "A"^"1" => "ArrayArray"[[]] ^ (1).[]
"🐱" => IntlChar::chr(0x1f431) => ["IntlChar", "chr"](0x1f431)
["cat", "meow"] => "str_getcsv"("cat,meow")
eval(PAYLOAD) => "create_function"("", PAYLOAD)() => "create_function"(...str_getcsv(",PAYLOAD"))()
```

實在不知道我弄出這個東西的意義是什麼 :)

然後裡面提到PHPFuck的小小缺點或許我之後會發個issue或送個pr之類的，如果我有空的話XD
