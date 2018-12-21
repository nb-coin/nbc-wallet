
### 1. 关于本项目

本项目（nbc-wallet）是与 Newborn Bitcoin（简称 NBC）产品配套的，由官方提供的钱包客户端 APP。NBC 是一个类似于比特币的产品，在 NBC 区块链上发行的币种称为 NBC 币，请访问 http://nb-coin.com 了解更多关于 NBC 的信息。

nbc-wallet 是开源产品，任何人可从 github.com/nb-coin/nbc-wallet 下载源码。

&nbsp;

### 2. 安装

nbc-wallet 用 python 开发，支持 Python3.4+ 版本，Windows 或 MAC 各版本的桌面操作系统平台均支持。

如果您当前所用的 Python 是 2.7 以下的版本，请先升级到 3.4 以上的版本。另外，nb-wallet 使用如下依赖库，也请自行安装：

``` bash
pip install six
pip install miniupnpc
pip install click
pip install requests
```

在 Python 运行环境准备就绪后，请用如下脚本获取 nbc-wallet 项目：

``` bash
git clone http://github.com/nb-coin/nbc-wallet.git
```

然后运行本软件：

``` bash
cd nbc-wallet
python wallet.py --help
```

&nbsp;

### 3. 命令行帮助

本软件提供如下子命令：

``` bash
  create
  info
  block
  utxo
  transfer
  record
```

使用 `python wallet.py <command> --help` 可查看针对子命令的参数提示。比如：

``` bash
python wallet.py create --help
python wallet.py info --help
```

&nbsp;

### 4. 使用指南：创建账号地址

运行如下脚本可创建一个名为 `addr1` 的账号，您将在 `data/account/` 下发现 `addr1.cfg` 配置文件。创建新账号时，系统会提示您输入密码，该密码用于加密新账号的私钥，然后私钥以密文方式保存到配置文件。

``` bash
python wallet.py create addr1
```

成功创建账号后，界面将打印该账号的 Base58 地址，如果想查看该账号的私钥，可用如下脚本：

``` bash
python wallet.py info --account addr1 --private
```

说明：
1. 慎用 `--private` 参数打印钱包地址的私钥，因为容易泄密，如果别人知道您的私钥，他有能力转走您在本地址拥有的 NBC 币。
2. `--account` 参数用于指定钱包 APP 当前使用哪个账号，并让这个账号用作缺省账号，下次使用时如果不用 `--account` 显式指定，仍自动使用这个账号。
3. 本软件所有命令都启用了 `--password` 参数，如果 password 未在参数给出，系统会提示您输入当前账号加密私钥所用的密码。我们推荐大家在命令行输入密码，而不借助参数传递，因为用参数传递容易泄露密钥明文。

&nbsp;

### 5. 使用指南：使用已知的私钥来创建账号

``` bash
python wallet.py create --private addr2
```

当系统提示输入 `Private key` 时，可拷贝私钥文本，粘贴过去，击回车完成输入。

&nbsp;

### 6. 使用指南：查看账户信息

执行如下脚本可查看当前账号信息，包括 Base58 地址与在线查得的 NBC 余额。

``` bash
python wallet.py info
```

如果只显示当前账号的 Base58 地址，不查余额，可用如下脚本：

``` bash
python wallet.py info --public
```

不切换当前账号，查询其它的指定地址下的余额：

``` bash
python wallet.py info 1112pzQBWmUCsLtFZ1oNV769viSdDnAPX45N7Xp3zKvDPJwAL8BJFS
```

NBC 采用类似比特币的 UTXO 账户模型，一个账号的总余额为它所拥有的所有未花费用（即 UTXO）项的总和。UTXO 记录项由 uock 索引，特定 uock 唯一对应一项 UTXO，查询账户余额时，还可由 `--after uock` 及（或） `-before uock` 参数来限定查询范围。比如：

``` bash
python wallet.py info --after 442003675414528
```

如果 `--after uock1` 与 `--before uock2` 两个参数并用，表示限制范围为 `uock1 < uock <= uock2` 。

&nbsp;

### 7. 使用指南：查询 UTXO

显示当前账号拥有的 UTXO 详情信息，缺省显示最近 5 条 UTXO 记录。

``` bash
python wallet.py utxo
```

我们还可以用 `--num n` 参数指定只显示最近 n 条记录，n 在 1 ~ 100 之间取值，也可用 `--uock id` 指定只显示一条对应的记录。

除了当前账号，还可查询其它指定账号的 UTXO，比如：

``` bash
python wallet.py utxo 1112pzQBWmUCsLtFZ1oNV769viSdDnAPX45N7Xp3zKvDPJwAL8BJFS
```

&nbsp;

### 8. 使用指南：浏览指定高度的区块信息

``` bash
python wallet.py block 0 1-
```

一次可查阅一个或多个区块，比如上面脚本，查阅高度为 0 的区块（即创始区块）以及最后一个区块的信息，块高若带 `-` 后缀表示从当前区块链的最后一个区块向前倒数，`1-` 表示倒数第一个区块，`2-` 倒数第二个区块，其它类推。

我们还可以用 `--hash id` 查询指定区块头哈希值的区块，比如：

``` bash
python wallet.py block --hash 9488469356089fea9638efa2bb61ab0740b2037178292bdd665933b0d3020000
```

&nbsp;

### 9. 使用指南：转账

从当前账号向指定账号转账，比如：

``` bash
python wallet.py transfer 1112pzQBWmUCsLtFZ1oNV769viSdDnAPX45N7Xp3zKvDPJwAL8BJFS=5.5
```

上面脚本含义为：从当前账号向 `1112pzQBWmUCsLtFZ1oNV769viSdDnAPX45N7Xp3zKvDPJwAL8BJFS` 转账 5.5 NBC 币，如果要向多个账号转账，罗列多个由 `=` 串接的目标账号及转账额的项目即可。转账请求发起后，本程序将持续发起进度查询，每隔数十秒查询一次转账进度，进度信息将打印到界面。若想停止查询，可按 `Ctrl + C` 链中断。

每次转账系统将计算该交易单的哈希值，此哈希值将唯一代表本交易，即用作交易 ID，在交易刚发起时，界面会打印输出本次交易的哈希值。此后，我们可用类似如下脚本再次查询该交易的进度：

``` bash
python wallet.py transfer --hash e11e110060d16c77579d00cb105298c52b228f01664dcd9361ffae82b31cdffa
```

成功提交一项交易后，界面将打印动用当前账号中的最后一个 utxo 的 ID 值（即 uock 值），在紧接着的同一账号向外转帐时，可用 `--after uock` 指示从指定位置之后取 UXTO 来转账，这有助于避免同一 UTXO 在两次转账中均被使用。

&nbsp;

### 10. 使用指南：存证

nbc-wallet 支持短消息存证与哈希值存证。前者用于在区块链账本数据中保存简短信息，后者只保存一段哈希字串，哈希字串则来源于对一篇文章或一长字串进行散列运算。

短消息存证可支持存入 72 个字符的内容，使用举例如下：

``` bash
python wallet.py record "Hello world!" "This is second line"
```

多行存证内容可用多个字串以传入参数形式来表达，如上有两行消息被存证。

哈希值存证用 `--proof` 参数指示，再传入某个哈希值即可，举例如下：

``` bash
python wallet.py record --proof ba125434cf56d1b265b4f05e788b838a0bbbd89d0dfd3b3ec1452488552d80b1
```

本软件也将存证（包括短消息存证与哈希值存证）视作一项交易，与 `transfer` 子命令类似，也支持用 `--hash` 指定交易 ID 来查询交易进度，比如：

``` bash
python wallet.py record --hash a99718b42488efad73424511ac7e6cb4e9a7c9b200dca7182fb9eb67f023f267
```

&nbsp;

### 11. 软件集成与交互式调试

nbc-wallet 作为 NBC 区块链的客户端钱包 APP，其主体功能，包括交易与信息查询，要通过调用在 `https://api.nb-coin.com` 提供的 RESTful API 服务来实现。因为本软件已开源，全部代码可从 github 下载过来研读，所以，本项目也是 NBC 区块链 RESTful API 一种实现样例，大家可以仿照着将源码移植到 java、javascript 等运行环境下使用。

如果想用交互式命令行调试本软件，不妨以 `-i` 参数启动 python，比如：

``` bash
python -i wallet.py --help
```

&nbsp;

### 12. 关于版权

nbc-wallet 重用了 [ricmoo/pycoind](https://github.com/ricmoo/pycoind) 项目中的 util 模块代码，该模块我们维持原有的 MIT 授权证书。

本项目其它源码我们采用 MPL V2 开源协议，详见：[MPL 2.0](http://mozilla.org/MPL/2.0/)

任何问题请在 [github nb-coin/nbc-wallet 项目](https://github.com/nb-coin/nbc-wallet) 的 Issues 页中提交，谢谢关注本项目！

&nbsp;
