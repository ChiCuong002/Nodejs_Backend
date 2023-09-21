'use strict'

const crypto = require('crypto')

const createKeyToken = () => {
    return crypto.randomBytes(64).toString('hex')
}

module.exports = {
    createKeyToken
}