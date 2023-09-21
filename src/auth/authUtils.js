'use strict'
const JWT = require('jsonwebtoken')
const  asyncHandler  = require('../helpers/asyncHandler')
const { AuthFailureError, NotFoundError } = require('../core/error.response')
//service
const { findeByUserId } = require('../services/keyToken.service')
const HEADER = {
    API_KEY: 'x-api-key',
    CLIENT_ID: 'x-client-id',
    AUTHORIZATION: 'authorization'
}

const createTokenPair = async( payload, publicKey, privateKey ) => {
    try {
        //create an access token
        const accessToken = await JWT.sign(payload, publicKey, {
            //algorithm: 'RS256', cách 1
            expiresIn: '2 days'
        })
        const refreshToken = await JWT.sign( payload, privateKey, {
            //algorithm: 'RS256', cách 1
            expiresIn: '7 days'
        })
        JWT.verify(accessToken, publicKey, (err, decode) => {
            if(err){
                console.log('error verify::', err)
            } else {
                console.log('decode verify::', decode)
            }
        })

        return {accessToken, refreshToken}
    } catch (error) {
        
    }
}
const authentication = asyncHandler( async (req, res, next) => {
    /*
        1- Check userId missing ?
        2- get accessToken
        3- verify token
        4- check user in dbs ?
        5- check keyStore with this userId
        6- all ok -> return next()
    */
   //1.
   const userId = req.headers[HEADER.CLIENT_ID]
   if(!userId) throw new AuthFailureError('Error: Invalid Request')

   //2.
   const keyStore = await findeByUserId(userId)
   if(!keyStore) throw new NotFoundError('Error: Not Found keyStore')

   //3.
   const accessToken = req.headers[HEADER.AUTHORIZATION]
   if(!accessToken) throw new AuthFailureError('Error: Invalid Request accessToken')

   try {
        const decodeUser = JWT.verify(accessToken, keyStore.publicKey)
        if(userId !== decodeUser.userId){
            throw new AuthFailureError('Error: Invalid User')
        }
        req.keyStore = keyStore
        return next()
   } catch (error) {
        throw error
   }
})

module.exports = {
    createTokenPair,
    authentication
}