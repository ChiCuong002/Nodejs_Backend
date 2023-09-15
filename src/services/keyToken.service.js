'use strict'

const keytokenModel = require("../models/keytoken.model")

class KeyTokenService {
    static createKeyToken = async ({userId, publicKey, privateKey}) => {
        try {
            //const publicKeyString = publicKey.toString() cách 1
            const tokens = await keytokenModel.create({
                user: userId,
                publicKey, 
                privateKey
            })
            return tokens ? tokens.publicKey : null
        } catch (error) {
            return error
        }
    }
}

module.exports = KeyTokenService