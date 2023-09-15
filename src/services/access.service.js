'use strict'

const shopModel = require('../models/shop.model')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const KeyTokenService = require('./keyToken.service')
const { createTokenPair } = require('../auth/authUtils')
const { getInfoData } = require('../utils')
const RoleShop = {
    SHOP: 'SHOP',
    WRITER: 'WRITER',
    EDITOR: 'EDITOR',
    ADMIN: 'ADMIN',
}

class AccessService {

    static signUp = async ({name, email, password}) => {
        try {
            //step 1: check email exists ?
            const holderShop = await shopModel.findOne({ email }).lean()
            if(holderShop){
                return {
                    code: 'xxxx',
                    message: 'Shop already registered!'
                }
            } 
            const passwordHash = await bcrypt.hash(password, 10)
            const newShop = await shopModel.create({
                name, email, password: passwordHash, roles: [RoleShop.SHOP]
            })
            if(newShop){
                //create privateKey, publicKey
                const privateKey = crypto.randomBytes(64).toString('hex') //cách 2
                const publicKey = crypto.randomBytes(64).toString('hex')

                // CÁCH 1 
                // const {privateKey, publicKey} = crypto.generateKeyPairSync('rsa', {
                //     modulusLength: 4096,
                //     publicKeyEncoding: {
                //         type: 'pkcs1', // Public Key CryptoGraphy Standards !
                //         format: 'pem'
                //     },
                //     privateKeyEncoding: {
                //         type: 'pkcs1',
                //         format: 'pem'
                //     }
                // })

        
                //save key
                const keyStore = await KeyTokenService.createKeyToken({
                    userId: newShop._id,
                    publicKey,
                    privateKey
                })
                if(!keyStore){
                    return {
                        code: 'xxxx',
                        message: 'publicKeyString error'
                    }
                }
                //convert publicKeyString get from database
                // const publicKeyObject = crypto.createPublicKey(publicKeyString) cách 1
                // console.log('publicKeyObject::', publicKeyObject) cách 1
                //create token pair
                const tokens = await createTokenPair({userId: newShop._id, email}, publicKey, privateKey)
                console.log('Created Token Success::', tokens)
                return {
                    code: 201,
                    metadata: {
                        shop: getInfoData({ fileds: ['_id', 'name', 'email'], object: newShop }),
                        tokens
                    }
                }
            }
            return {
                code: 200,
                metadata: null
            }
        } catch (error) {
            return {
                code: 'xxx',
                message: error.message,
                status: 'error'
            }
        }
    }
}

module.exports = AccessService