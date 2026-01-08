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

    guard let keyData = hexToBytes(hexKey) else { return nil }

    let key = SymmetricKey(data: keyData)
    do {
      let sealedBox = try AES.GCM.seal(text, using: key)

      var combined = Data()
      combined.append(sealedBox.ciphertext)
      combined.append(sealedBox.tag)

      return "\(Data(sealedBox.nonce).base64EncodedString()):\(combined.base64EncodedString())"
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
    let cipherData = ciphertextBase64.split(separator: ":")
      guard let ivData = Data(base64Encoded: String(cipherData[0])) else { return nil }
    guard let combinedData = Data(base64Encoded: String(cipherData[1])) else {
      return nil
    }
    let cipherText = combinedData.prefix(combinedData.count - 16)

    let tagData = combinedData.suffix(16)

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
