const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
      name: String,
    email: String,
    role: String,
    bal: Number
    
    
});


module.exports = mongoose.model('User', schema);