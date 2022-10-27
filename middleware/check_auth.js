const jwt = require('jsonwebtoken');

module.exports = (req, res) => {
    try{
        const token = req.headers.authorization.split(' ')[1]
        const decode = jwt.verify(token, process.env.SECRET_KEY)
        res.locals.user = decode;
        next()
    }
    catch(error){
        res.status(500).json({
            msg : error.message
        })
    }
}