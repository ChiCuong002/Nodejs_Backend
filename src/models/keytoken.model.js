'use strict'

const {Schema, model, Types} = require('mongoose');

const DOCUMENT_NAME = 'Key'
const COLLECTION_NAME = 'Keys'
// Declare the Schema of the Mongo model
var keyTokenSchema = new Schema({
    user:{
        type: Schema.Types.ObjectId,
        required:true,
        ref: 'Shop'
    },
    privateKey:{
        type: String,
        required:true
    },
    publicKey:{
        type: String,
        required:true
    },
    refreshTokenUsed: { // nhung RT da duoc su dung
        type: Array,
        default: []
    },
    refreshToken: {
        type: String,
        required: true
    }
}, {
    collection: COLLECTION_NAME,
    timestamps: true
});

//Export the model
module.exports = model(DOCUMENT_NAME, keyTokenSchema);