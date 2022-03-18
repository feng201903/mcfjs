const nacl = require('tweetnacl');
const ed2curve = require('ed2curve');
const sha256 = require('crypto-js/sha256');
const encHex = require('crypto-js/enc-hex');
const ripemd160 = require('crypto-js/ripemd160');

const Base58 = require('./js/Base58');

const Mnemonic = require('./js/jsbip39');
const mnemo = new Mnemonic("english")



class Mcf {
  addresses = {}
  constructor(mnemonic) {
    if (mnemonic) {
      if (!mnemo.check(mnemonic)) throw new Error('Invalid mnemonic !')
      let hexStr = mnemo.revertEntropy(mnemonic)
      this.privateKey = this.haxStrToPrk(hexStr)
    }
  }

  get privateKey() {
    return this.addresses.privateKey
  }
  set privateKey(val) {
    let addresses = this.addresses
    addresses.privateKey = val
    addresses.publicKey = this.prkToPuk(val)
    addresses.address = this.pukToAddress(addresses.publicKey)
  }

  createAddress(randomByte) {
    if (!randomByte || randomByte.length !== 16) throw new Error('Data length should be 16')
    randomByte = randomByte.subarray(0, 16)
    this.privateKey = this.haxStrToPrk(this._u8ArrayToHexStr(randomByte))
    this.addresses.mnemonic = mnemo.toMnemonic(randomByte)
    return this.addresses
  }

  haxStrToPrk(hexStr) {
    let haxStrHashSHA256 = sha256(encHex.parse(hexStr)).toString(),
      prkU8Array = this._hexStrToU8Array(haxStrHashSHA256)
    return Base58.encode(prkU8Array)
  }

  prkToPuk(privateKey) {
    let prkKeyPair = nacl.sign.keyPair.fromSeed(Base58.decode(privateKey))
    return Base58.encode(prkKeyPair.publicKey)
  }

  pukToAddress(publicKey) {
    let pukHashHex = this._u8ArrayToHexStr(Base58.decode(publicKey)),
      pukHashSHA256 = sha256(encHex.parse(pukHashHex)).toString(),
      pukHashRIPEMD160 = ripemd160(encHex.parse(pukHashSHA256)).toString(),
      addressU8Array = this._concatUint8Arrays(new Uint8Array([58]), this._hexStrToU8Array(pukHashRIPEMD160)),
      addressHashSHA256 = sha256(sha256(encHex.parse(this._u8ArrayToHexStr(addressU8Array)))).toString(),
      checkSum = this._hexStrToU8Array(addressHashSHA256);
    addressU8Array = this._concatUint8Arrays(addressU8Array, checkSum.subarray(0, 4))
    return Base58.encode(addressU8Array)
  }


  getProxyPrivateKey(privateKey, publicKey) {
    let curveSecretKey = ed2curve.convertSecretKey(Base58.decode(privateKey))
    let mintingX25519KeyPair = nacl.box.keyPair.fromSecretKey(curveSecretKey)
    let recipientAccountX25519Puk = ed2curve.convertPublicKey(Base58.decode(publicKey))
    let sharedSecret = nacl.scalarMult(mintingX25519KeyPair.secretKey, recipientAccountX25519Puk)
    let sharedSecretSHA256 = sha256(encHex.parse(this._u8ArrayToHexStr(sharedSecret))).toString()
    let proxyPrivateKey = Base58.encode(this._hexStrToU8Array(sharedSecretSHA256))
    return proxyPrivateKey
  }

  signTransaction(opt) {
    if (!opt || !opt.txType || !this._signConfig[opt.txType]) throw new Error('txType Invalid!');
    let config = this._signConfig[opt.txType]
    for (let k in config.required) {
      if (!opt[config.required[k]]) {
        throw new Error(config.required[k] + ' is required!');
      }
    }
    opt.txTypeID = config.txTypeID
    let hexTxTypeID = this._zeroFill(opt.txTypeID, 8),
      timestamp = this._zeroFill(new Date().getTime(), 16),
      txGroupId = '00000000',
      reference = this._u8ArrayToHexStr(Base58.decode(opt.reference)),
      prkKeyPair = nacl.sign.keyPair.fromSeed(Base58.decode(this.privateKey)),
      spk = this._u8ArrayToHexStr(prkKeyPair.publicKey),
      fee = opt.fee || 0.00001,
      signStr = this._signfn(opt)
    fee = this._zeroFill(fee, 16, 100000000)
    signStr = hexTxTypeID + timestamp + txGroupId + reference + spk + signStr + fee
    let trBytes = this._hexStrToU8Array(signStr);
    let dc = nacl.sign.detached(trBytes, prkKeyPair.secretKey);
    let signature = Base58.encode(new Uint8Array(dc))
    let transaction = Base58.encode(this._concatUint8Arrays(trBytes, dc))
    return {
      signature,
      transaction
    }
  }

  _signfn(opt) {
    let signStr;
    opt.recipient = opt.recipient && this._u8ArrayToHexStr(Base58.decode(opt.recipient))
    switch (opt.txType) {
      case "PAYMENT":
        opt.amount = this._zeroFill(opt.amount, 16, 100000000);
        signStr = opt.recipient + opt.amount;
        break;
      case "TRANSFER_ASSET":
        opt.amount = this._zeroFill(opt.amount, 24, 100000000);
        opt.assetId = this._zeroFill(opt.assetId, 16);
        signStr = opt.recipient + opt.assetId + opt.amount;
        break;
      case "JOIN_GROUP":
        opt.groupId = this._zeroFill(opt.groupId, 8);
        signStr = opt.groupId;
        break;
      case "ENABLE_FORGING":
        signStr = opt.recipient;
        break;
      case "PROXY_FORGING":
        opt.proxyPuk = this._u8ArrayToHexStr(
          nacl.sign.keyPair.fromSeed(Base58.decode(opt.proxyPrivateKey))
          .publicKey
        );
        opt.share = this._zeroFill(opt.share, 16, 100000000);
        signStr = opt.recipient + opt.proxyPuk + opt.share;
        break;
      case "ISSUE_ASSET":
        opt.owner = this._u8ArrayToHexStr(Base58.decode(opt.owner))
        opt.aNameL = this._zeroFill(opt.assetName.length, 8)
        opt.aName = this._strToHexCharCode(opt.assetName)
        opt.description = encodeURIComponent(opt.zhName)
        opt.descL = this._zeroFill(opt.description.length, 8)
        opt.desc = this._strToHexCharCode(opt.description)
        opt.quantity = this._zeroFill(opt.quantity, 16);
        opt.isDivisible = "00";
        opt.data = JSON.stringify({
          'logo': opt.logo,
          'full': encodeURIComponent(opt.fullName),
          'url': opt.url,
          'web': opt.web,
          'content': encodeURIComponent(opt.content)
        })
        opt.dataL = this._zeroFill(opt.data.length, 8)
        opt.data = this._strToHexCharCode(opt.data)
        signStr = opt.owner + opt.aNameL + opt.aName + opt.descL + opt.desc + opt.quantity + opt.isDivisible + opt.dataL + opt.data;
        break;
      case 'UPDATE_GROUP':
        opt.groupId = this._zeroFill(opt.groupId, 8)
        opt.owner = this._u8ArrayToHexStr(Base58.decode(opt.owner))
        opt.desL = this._zeroFill(opt.description.length, 8);
        opt.des = this._strToHexCharCode(opt.description)
        opt.isOpen = opt.isOpen ? '01' : '00'
        opt.threshold = this._zeroFill(opt.approvalThreshold, 2)
        opt.min = this._zeroFill(opt.minimumBlockDelay, 8);
        opt.max = this._zeroFill(opt.maximumBlockDelay, 8);
        signStr = opt.groupId + opt.owner + opt.desL + opt.des + opt.isOpen + opt.threshold + opt.min + opt.max
        break;
      case 'ADD_GROUP_ADMIN':
        opt.groupId = this._zeroFill(opt.groupId, 8)
        signStr = opt.groupId + opt.recipient
        break;
      case 'REMOVE_GROUP_ADMIN':
        opt.groupId = this._zeroFill(opt.groupId, 8)
        signStr = opt.groupId + opt.recipient
        break;
      default:
        throw new Error(`Signature failed! ${opt.txType}`)
    }
    return signStr
  }

  _signConfig = {
    'PAYMENT': {
      txTypeID: 2,
      required: ['reference', 'recipient', 'amount']
    },
    'ISSUE_ASSET': {
      txTypeID: 11,
      required: ["reference", "assetName", "zhName", "fullName", "logo", "content", "url", "web", "quantity"],
    },
    'TRANSFER_ASSET': {
      txTypeID: 12,
      required: ['reference', 'recipient', 'amount', 'assetId']
    },
    'UPDATE_GROUP': {
      txTypeID: 23,
      required: ['reference', 'groupId', 'owner', 'description', 'isOpen', 'approvalThreshold', 'minimumBlockDelay', 'maximumBlockDelay']
    },
    'ADD_GROUP_ADMIN': {
      txTypeID: 24,
      required: ['reference', 'groupId', 'recipient']
    },
    'REMOVE_GROUP_ADMIN': {
      txTypeID: 25,
      required: ['reference', 'groupId', 'recipient']
    },
    'JOIN_GROUP': {
      txTypeID: 31,
      required: ['reference', 'groupId']
    },
    'ENABLE_FORGING': {
      txTypeID: 37,
      required: ['reference', 'recipient']
    },
    'PROXY_FORGING': {
      txTypeID: 38,
      required: ['reference', 'recipient', 'proxyPrivateKey', 'share']
    },

  }

  _u8ArrayToHexStr(bs) {
    return bs.reduce((prev, curr) => prev += curr.toString(16).padStart(2, '0'), '')
  }

  _hexStrToU8Array(s) {
    var result = new Uint8Array(s.length / 2);
    for (var i = 0; i < s.length / 2; i++) {
      result[i] = parseInt(s.substr(2 * i, 2), 16);
    }
    return result;
  }

  _strToHexCharCode(str) {
    return str
      .split("")
      .reduce((prev, curr) => (prev += curr.charCodeAt(0).toString(16)), "");
  }

  _concatUint8Arrays(array1, array2) {
    var bigArray = new Uint8Array(array1.length + array2.length)
    bigArray.set(array1, 0)
    bigArray.set(array2, array1.length)
    return bigArray
  }

  _zeroFill(str, length, enlarge = 1) {
    return parseInt(str * enlarge).toString(16).padStart(length, "0")
  }
}

module.exports = Mcf