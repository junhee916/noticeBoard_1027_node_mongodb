const mongoose = require('mongoose')

const modelSchema = mongoose.Schema(
    {
        user : {
            type : mongoose.Schema.Types.ObjectId,
            ref : "user",
            required : true
        },
        board : {
            type : mongoose.Schema.Types.ObjectId,
            ref : "board"
        },
        commend : {
            type : String,
            required : true
        }
    },
    {
        timestamps : true
    }
)

module.exports = mongoose.model('commend', modelSchema)