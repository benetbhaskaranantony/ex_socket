var ExamUser = require('../models/examuser');
const findone = async function (val) {
   // console.log(val)
         ExamUser.findOne({ "mac": val }, async (err, result) => {
            if (!err) {
               // console.log(result)
                return result;
            } else {
                return err;
            }
        })
    
}

module.exports = {
    findone
}