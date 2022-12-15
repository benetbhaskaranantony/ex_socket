const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
   "username": {type:String},
  "password": {type:String},
  "mac": {type:String},
  "isActive": {type:Number},
  "email": { type: String },
  "role": String,
  "bal": Number,
  "socket":String
    
});


module.exports = mongoose.model('Examuser', schema);