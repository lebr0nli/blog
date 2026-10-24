---
title: "Z3 Theorem Prover在CTF的簡單應用"
date: 2022-01-22 00:13:00 +0800
tags:
  - CTF
  - Write-up
  - Reverse Engineering
  - Z3
categories:
  - Security
---

Case study: KnightCTF 2022 - Flag Checker

## Intro

這次有人找我一起參加KnightCTF，我主要負責Web的題目，但也幫忙解了一題pwn和兩題reverse。

這場CTF應該是我參加過最差勁的一場CTF，題目各種需要通靈，Web只有兩題有給source code，剩下全部都只能猜，很沒意思，不僅如此，這場主辦方的server也是超級不穩定，連交個flag也要卡個幾分鐘...，總之你不期望在CTF中看到的東西，這場都出現了...

雖然這場真的蠻爛的，但還是讓我學到了一些關於Z3 Theorem Prover的知識，

由於maple3142常常會跟我分享他又用Z3把什麼題目的flag給炸出來，導致我也一直想要實際用Z3來解題，

而剛好這場CTF的reverse水到不行，所以我也藉這個機會學習了一下Z3。

以下紀錄我用Z3解掉的其中一題，希望可以幫助到跟我一樣只看過Z3基本介紹、但從沒實際用過Z3的人。

> Note: 由於我對於Z3還沒有非常熟悉，如果有地方寫的很髒，還請見諒。

## Flag Checker

### Overview

題目給了一個ELF，丟進ida再整理一下過後的Pseudocode為：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char flag[512]; // [rsp+0h] [rbp-240h] BYREF
  char v5[51]; // [rsp+200h] [rbp-40h] BYREF
  char is_flag; // [rsp+233h] [rbp-Dh]
  int v7; // [rsp+234h] [rbp-Ch]
  int j; // [rsp+238h] [rbp-8h]
  int i; // [rsp+23Ch] [rbp-4h]

  strcpy(v5, "08'5[Z'Y:H3?X2K3V)?D2G3?H,N6?G$R(G]");
  printf("Give me a flag : ");
  __isoc99_scanf("%s", flag);
  for ( i = 0; flag[i]; ++i )
  {
    if ( flag[i] <= 64 || flag[i] > 90 )
    {
      if ( flag[i] <= 96 || flag[i] > 122 )
        flag[i] = flag[i];
      else
        flag[i] = -37 - flag[i];
    }
    else
    {
      flag[i] = -101 - flag[i];
    }
  }
  for ( j = 0; flag[j]; ++j )
    flag[j] -= 32;
  v7 = 0;
  is_flag = 0;
  while ( v5[v7] )
  {
    if ( v5[v7] != flag[v7] )
    {
      is_flag = 0;
      break;
    }
    is_flag = 1;
    ++v7;
  }
  if ( is_flag )
    puts("You have entered the right flag.");
  else
    puts("Sorry ! Its wrong flag.");
  return 0;
}
```

首先可以看到，這題會讀取一串使用者的輸入，再用for迴圈遍歷，再根據某些規則(~~魔法~~)對每一個char的ASCII做加減法，

接下來再將每個char的ASCII - 32，再與`v5`做比對，如果array中每個char一樣，就找到flag了。

### Solution

這題其實可以不用Z3，因為蠻好推回去的，但秉持學習(~~懶惰~~)的精神，所以選擇用Z3來解

首先，我用的是Python的Z3，所以第一步當然就是把Z3給import進來：

```python
from z3 import *
```

而這題的目標是:'flag經過一連串的"魔法"之後，會與v5相同'，所以我們先將`v5`這個char arrary給建起來:

```python
target = b"08'5[Z'Y:H3?X2K3V)?D2G3?H,N6?G$R(G]"
```

接下來，我們需要創建一個儲存flag的陣列，而陣列中的每個char我使用8 bit的`BitVec`來儲存:

```python
flag = [BitVec(f"f_{i}", 8) for i in range(len(target))]
```

> Note: BitVec('變數名稱', 大小)
>
> 值得注意的是BitVec跟C的變數一樣，會Underflow/Overflow，且效果是一樣的，所以不需要而外處理

還有其實也可以用Z3的`Array`，但可能是我對Z3還不夠熟，所以我自己覺得這個操作起來不太方便就是了:

```python
flag = Array("flag", BitVecSort(32), BitVecSort(8))
# 存取的時候index要用BitVecVal，寫入的時候要用Store
```

接下來我們要做的，就是根據題目的規則把flag運算之後加上約束:

首先我們先將Z3的`Solver`給建起來:

```python
s = Solver()
```

由於我們知道最終flag的格式，我們可以先將此格式的約束加上去:

```python
for i, c in enumerate(b"KCTF{"):
    s.add(flag[i] == c)
s.add(flag[-1] == ord("}"))
```

接下來是重頭戲，我們首先先根據題目的邏輯，遍歷flag的每個char:

```python
for i in range(len(target)):
```

總共可以看到兩個判斷:

```c
flag[i] <= 64 || flag[i] > 90
```

還有:

```c
flag[i] <= 96 || flag[i] > 122
```

我們將他用Z3表達出來:

```python
cond1 = Or(flag[i] <= 64, flag[i] > 90)
cond2 = Or(flag[i] <= 96, flag[i] > 122)
```

接來根據題目把if的邏輯建起來:

```python
flag[i] = If(cond1, If(cond2, flag[i], -37 - flag[i]), -101 - flag[i])
```

> Note: If(condition, 成立時的回傳值, 不成立時的回傳值)

再減掉32:

```python
flag[i] = flag[i] - 32
```

加上約束:

```python
s.add(flag[i] == target[i])
```

接下來Z3就會幫我們把flag求出來了!

最後，我們只需確定`s.check()`是`sat`，再將`s.model`裡的答案全部拿出來就可以了：

```python
assert s.check() == sat
m = s.model()
flag = bytes([m[x].as_long() for x in flag_init]).decode()
print(flag)
```

> Note: `flag_init`是最一開始`flag`的`flag.copy()`，用來記錄每個變數，方便最後依照順序print出來，這個部分方法很多，也可以最後再依照名稱做sorting

Full script:

```python
from z3 import *


def main():
    target = b"08'5[Z'Y:H3?X2K3V)?D2G3?H,N6?G$R(G]"
    flag = [BitVec(f"f_{i}", 8) for i in range(len(target))]
    flag_init = flag.copy()
    s = Solver()
    for i, c in enumerate(b"KCTF{"):
        s.add(flag[i] == c)
    s.add(flag[-1] == ord("}"))
    for i in range(len(target)):
        cond1 = Or(flag[i] <= 64, flag[i] > 90)
        cond2 = Or(flag[i] <= 96, flag[i] > 122)
        flag[i] = If(cond1, If(cond2, flag[i], -37 - flag[i]), -101 - flag[i])
        flag[i] = flag[i] - 32
        s.add(flag[i] == target[i])

    assert s.check() == sat

    m = s.model()
    flag = bytes([m[x].as_long() for x in flag_init]).decode()
    print(flag)


if __name__ == '__main__':
    main()

```

flag: `KCTF{aTbAsH_cIpHeR_wItH_sOmE_tWiSt}`

## Summary

Z3真的是很強大的工具，只要借助Z3，不太需要太多思考，就可以輕鬆把問題解掉。

也蠻高興的，這次終於有機會在實戰中應用出來了~
