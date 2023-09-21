'use strict'

const shopModel = require('../models/shop.model')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const KeyTokenService = require('./keyToken.service')
const { createTokenPair } = require('../auth/authUtils')
const { getInfoData } = require('../utils')
const { BadRequestError, AuthFailureError } = require('../core/error.response')
const { findByEmail } = require('./shop.service')
const { createKeyToken } = require('../utils/createKeyToken')
const { create } = require('lodash')
const RoleShop = {
    SHOP: 'SHOP',
    WRITER: 'WRITER',
    EDITOR: 'EDITOR',
    ADMIN: 'ADMIN',
}

class AccessService {
    static logout = async ( keyStore ) => {
        const delKey = await KeyTokenService.removeKeyById( keyStore._id )
        console.log({delKey})
        return delKey
    }
    /*
            1- Check email in dbs
            2- match password
            3- create AT and RT and save
            4- general tokens
            5- get data return login
    */
    static login = async ({ email, password, refreshToken = null}) => {
        //1.
        const foundShop = await findByEmail({ email })
        console.log(foundShop)
        if(!foundShop){
            throw new BadRequestError('Error: Shop not registered')
        }
        //2.
        const match = bcrypt.compare(password, foundShop.password)
        if(!match){
            throw new AuthFailureError('Error: Authentication error')
        }
        //3.
        const privateKey = createKeyToken()
        const publicKey = createKeyToken()
        //4.
        const {_id: userId} = foundShop
        const tokens = await createTokenPair({userId , email}, publicKey, privateKey)
        
        await KeyTokenService.createKeyToken({
            refreshToken: tokens.refreshToken,
            privateKey,
            publicKey,
            userId
        })
        return {
                shop: getInfoData({ fileds: ['_id', 'name', 'email'], object: foundShop }),
                tokens
        }
    }

    static signUp = async ({name, email, password}) => {
        //try {
            //step 1: check email exists ?
            const holderShop = await shopModel.findOne({ email }).lean()
            if(holderShop){
                throw new BadRequestError('Error: Shop already register')
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
        // } catch (error) {
        //     return {
        //         code: 'xxx',
        //         message: error.message,
        //         status: 'error'
        //     }
        // }
    }
}

module.exports = AccessService