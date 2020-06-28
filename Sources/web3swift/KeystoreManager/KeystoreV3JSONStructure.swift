//  web3swift
//
//  Created by Alex Vlasov.
//  Copyright © 2018 Alex Vlasov. All rights reserved.
//

import Foundation
import CryptoSwift

public struct KdfParamsV3: Decodable, Encodable {
    var salt: String
    var dklen: Int
    var n: Int?
    var p: Int?
    var r: Int?
    var c: Int?
    var prf: String?
        
        public init(salt s:String, dklen d:Int, n N:Int?, p P:Int?, r R:Int?, c C:Int?, prf Prf:String?){
                salt = s
                dklen = d
                n = N
                p = P
                r = R
                c = C
                prf = Prf
        }
}

public struct CipherParamsV3: Decodable, Encodable {
        var iv: String
        public init(iv v:String){
                iv = v
        }
}

public struct CryptoParamsV3: Decodable, Encodable {
        var ciphertext: String
        var cipher: String
        var cipherparams: CipherParamsV3
        var kdf: String
        var kdfparams: KdfParamsV3
        var mac: String
        var version: String?
        
        public init(ciphertext ct:String,
                    cipher c:String,
                    cipherparams cp :CipherParamsV3,
                    kdf d:String,
                    kdfparams dp:KdfParamsV3,
                    mac m:String,
                    version v:String?) {
                ciphertext = ct
                cipher = c
                cipherparams = cp
                kdf = d
                kdfparams = dp
                mac = m
                version = v
        }
        
        public func derivePriKey(password:String) throws -> Data?{
                guard let saltData = Data.fromHex(self.kdfparams.salt) else {return nil}
                let derivedLen = self.kdfparams.dklen
                var passwordDerivedKey:Data?
                switch self.kdf {
                case "scrypt":
                        guard let N = self.kdfparams.n else {return nil}
                        guard let P = self.kdfparams.p else {return nil}
                        guard let R = self.kdfparams.r else {return nil}
                        passwordDerivedKey = scrypt(password: password, salt: saltData, length: derivedLen, N: N, R: R, P: P)
                case "pbkdf2":
                        guard let algo = self.kdfparams.prf else {return nil}
                        var hashVariant:HMAC.Variant?;
                        switch algo {
                                case "hmac-sha256" :
                                    hashVariant = HMAC.Variant.sha256
                                case "hmac-sha384" :
                                    hashVariant = HMAC.Variant.sha384
                                case "hmac-sha512" :
                                    hashVariant = HMAC.Variant.sha512
                                default:
                                    hashVariant = nil
                            }
                            guard hashVariant != nil else {return nil}
                            guard let c = self.kdfparams.c else {return nil}
                            guard let passData = password.data(using: .utf8) else {return nil}
                            guard let derivedArray = try? PKCS5.PBKDF2(password: passData.bytes, salt: saltData.bytes, iterations: c, keyLength: derivedLen, variant: hashVariant!).calculate() else {return nil}
                        
                            passwordDerivedKey = Data(derivedArray)
                default:
                        return nil
                }
                
                guard let derivedKey = passwordDerivedKey else {return nil}
                var dataForMAC = Data()
                let derivedKeyLast16bytes = Data(derivedKey[(derivedKey.count - 16)...(derivedKey.count - 1)])
                dataForMAC.append(derivedKeyLast16bytes)
                guard let cipherText = Data.fromHex(self.ciphertext) else {return nil}
                if (cipherText.count != 32) {return nil}
                dataForMAC.append(cipherText)
                let mac = dataForMAC.sha3(.keccak256)
                guard let calculatedMac = Data.fromHex(self.mac), mac.constantTimeComparisonTo(calculatedMac) else {return nil}
                
                let decryptionKey = derivedKey[0...15]
                guard let IV = Data.fromHex(self.cipherparams.iv) else {return nil}
                var decryptedPK:Array<UInt8>?
                switch cipher {
                case "aes-128-ctr":
                        guard let aesCipher = try? AES(key: decryptionKey.bytes, blockMode: CTR(iv: IV.bytes), padding: .noPadding) else {return nil}
                        decryptedPK = try aesCipher.decrypt(cipherText.bytes)
                case "aes-128-cbc":
                        guard let aesCipher = try? AES(key: decryptionKey.bytes, blockMode: CBC(iv: IV.bytes), padding: .noPadding) else {return nil}
                        decryptedPK = try? aesCipher.decrypt(cipherText.bytes)
                default:
                        return nil
                }
                guard decryptedPK != nil else {return nil}
                return Data(decryptedPK!)
        }
}

public struct KeystoreParamsV3: Decodable, Encodable {
        var address: String?
        var crypto: CryptoParamsV3
        var id: String?
        var version: Int

        public init(address ad: String?, crypto cr: CryptoParamsV3, id i: String, version ver: Int) {
                address = ad
                crypto = cr
                id = i
                version = ver
        }
}
