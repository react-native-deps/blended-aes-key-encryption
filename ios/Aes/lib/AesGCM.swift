//
//  AesGCM.swift
//  Aes
//
//  Created by Vatsal Mandloi on 06/01/26.
//  Copyright © 2026 tectiv3. All rights reserved.
//

import CryptoKit
import Foundation

@objcMembers
public class AesGCM: NSObject {

  public static func encrypt(
    hexString: String,
    hexKey: String,
  ) -> NSString? {

    guard let text = hexToBytes(hexString) else {
      return nil
    }
    guard let keyData = hexToBytes(hexKey) else {
      return nil
    }

    let key = SymmetricKey(data: keyData)
    do {
      let sealedBox = try AES.GCM.seal(text, using: key)

      guard let combined = sealedBox.combined else{
          return nil
      }

      return Data(combined).base64EncodedString()
            as NSString
    } catch {
      //print("Encryption failed: \(error.localizedDescription)")
      return nil
    }
  }

  public static func decrypt(
    ciphertextBase64: String,
    hexKey: String,
  ) -> String? {

    guard let keyData = hexToBytes(hexKey) else {
      return nil
    }

    guard let combinedData = Data(base64Encoded: String(ciphertextBase64)) else {
      return nil
    }

    let ivData = combinedData.prefix(12)
    let cipherAndTag = combinedData.dropFirst(12)
    let cipherText = cipherAndTag.dropLast(16)
    let tagData = cipherAndTag.suffix(16)
    let key = SymmetricKey(data: keyData)

    do {
      let nonce = try AES.GCM.Nonce(data: ivData)
      let box = try AES.GCM.SealedBox(
        nonce: nonce,
        ciphertext: cipherText,
        tag: tagData
      )
      let plainData = try AES.GCM.open(box, using: key)
      return bytesToHex(plainData)
    } catch {
      //print("Encryption failed: \(error.localizedDescription)")
      return nil
    }

  }

}
func bytesToHex(_ bytes: Data) -> String {
  let hexString = bytes.map { String(format: "%02x", $0) }.joined()
  return hexString
}
func hexToBytes(_ hex: String) -> Data? {
  var hexString = hex
  if hexString.hasPrefix("0x") {
    hexString = String(hexString.dropFirst(2))
  }

  guard hexString.count % 2 == 0 else {
    return nil  // Must be even-length
  }

  var bytes = Data()
  var index = hexString.startIndex

  while index < hexString.endIndex {
    let nextIndex = hexString.index(index, offsetBy: 2)
    let byteString = hexString[index..<nextIndex]
    if let byte = UInt8(byteString, radix: 16) {
      bytes.append(byte)
    } else {
      return nil  // Invalid hex digit
    }
    index = nextIndex
  }

  return bytes
}
