'use strict'

const keytokenModel = require("../models/keytoken.model")

class KeyTokenService {
    static createKeyToken = async ({userId, publicKey}) => {
        try {
            console.log(`userId: ${userId}, publicKey: ${publicKey}`)
            const publicKeyString = publicKey.toString()
            const tokens = await keytokenModel.create({
                user: userId,
                publicKey: publicKeyString
            })
            console.log("Tokens created:", tokens);
            return tokens ? publicKeyString : null
        } catch (error) {
            return error
        }
    }
}

module.exports = KeyTokenService