'use strict'
const JWT = require('jsonwebtoken')
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

module.exports = {
    createTokenPair
}