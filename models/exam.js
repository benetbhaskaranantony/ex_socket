const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
      username: String,
    password: String,
    subAdmin: String
    
    
});


module.exports = mongoose.model('Exam', schema);