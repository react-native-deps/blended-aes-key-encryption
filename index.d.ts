declare module 'react-native-aes-crypto' {
    type Algorithms = 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc'

    function encrypt(base64Data: string, hexKey: string, hexIv: string, algorithm: Algorithms): Promise<string>
    function decrypt(ciphertext: string, hexKey: string, hexIv: string, algorithm: Algorithms): Promise<string>
}
