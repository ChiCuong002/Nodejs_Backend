'use strict'

const keytokenModel = require("../models/keytoken.model")
const { Types } = require('mongoose')

class KeyTokenService {
    static createKeyToken = async ({userId, publicKey, privateKey, refreshToken}) => {
        try {
            // level 0
            //const publicKeyString = publicKey.toString() cách 1
            // const tokens = await keytokenModel.create({
            //     user: userId,
            //     publicKey, 
            //     privateKey
            // })
            // return tokens ? tokens.publicKey : null

            // level x
            const filter = { user: userId}, update = {
                publicKey, privateKey, refreshTokenUsed: [], refreshToken
            }, options =  {upsert: true, new: true} // upsert true new true neu co roi thi update con khong thi tao moi

            const tokens = await keytokenModel.findOneAndUpdate(filter, update, options)

            return tokens ? tokens.publicKey : null
        } catch (error) {
            return error
        }
    }
    static findeByUserId = async (userId) => {
        return await keytokenModel.findOne({ user: new Types.ObjectId(userId) }).lean()
    }
    static removeKeyById = async (id) => {
        return await keytokenModel.findOneAndDelete(id)
    }
}

module.exports = KeyTokenService