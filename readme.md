# MCF

## 引用

```
const Mcf = require('./dist/mcf.umd.min.js'); //nodejs

<script src="./dist/mcf.umd.min.js"></script> //browser
```

---
## 生成新钱包

```
//nodejs 
var crypto = require('crypto');
var randombytes = new Uint8Array(crypto.randomBytes(16))

//browser
var randombytes = crypto.getRandomValues(new Uint8Array(16));


var mcf = new Mcf()
var newAddr = mcf.createAddress(randombytes)
console.log(newAddr) 
/*
  {
    address: "QhvaBeJA4GNyuKUk59FZeZKUQRXhg1KRuS"
    mnemonic: "slogan where miracle copy solar tower menu update fold matrix stuff alarm"
    privateKey: "Gu6CrJKvmHrh5NJRUuGpFEdUT6PUJfb9rwBDLk7PnUD1"
    publicKey: "vffqkNaV8CSiMZYDKPqmuSegMRkTLhPfXV11mWw15Ti"
  }
*/
```

---

## 导入钱包
```
//通过助记词
var mnemonic = "slogan where miracle copy solar tower menu update fold matrix stuff alarm"
var mcf = new Mcf(mnemonic)
console.log(mcf.addresses)
/*
  {
    address: "QhvaBeJA4GNyuKUk59FZeZKUQRXhg1KRuS"
    privateKey: "Gu6CrJKvmHrh5NJRUuGpFEdUT6PUJfb9rwBDLk7PnUD1"
    publicKey: "vffqkNaV8CSiMZYDKPqmuSegMRkTLhPfXV11mWw15Ti"
  }
*/

//通过私钥
var mcf = new Mcf()
mcf.privateKey = 'Gu6CrJKvmHrh5NJRUuGpFEdUT6PUJfb9rwBDLk7PnUD1'
console.log(mcf.addresses)
/*
  {
    address: "QhvaBeJA4GNyuKUk59FZeZKUQRXhg1KRuS"
    privateKey: "Gu6CrJKvmHrh5NJRUuGpFEdUT6PUJfb9rwBDLk7PnUD1"
    publicKey: "vffqkNaV8CSiMZYDKPqmuSegMRkTLhPfXV11mWw15Ti"
  }
*/
```
---
   
## 交易签名

### 签名MCF转账

```
var mcf = new Mcf()
let opt = {
    txType: "PAYMENT",
    reference, //发送方reference
    recipient: "Qa4tXRd4PmH3U7hediRzKoVK7CYDmVziBM", //接收方地址
    amount: 1,
  };
var sign = mcf.signTransaction(opt)

//sign.transaction 签名后的交易信息 通过节点API http://localhost:9888/transactions/process提交至链上
//sign.signature 交易ID 转账提交后在链上查询详情


```

### 签名链上其他资产(非MCF)转账

```
var mcf = new Mcf()
let opt = {
    txType: "TRANSFER_ASSET",
    reference,  //发送方reference
    recipient: "Qa4tXRd4PmH3U7hediRzKoVK7CYDmVziBM", //接收方地址
    assetId: 1, //资产ID
    amount: 1,
  };
var sign = mcf.signTransaction(opt)

```

