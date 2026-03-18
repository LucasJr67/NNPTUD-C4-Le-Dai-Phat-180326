let jwt = require('jsonwebtoken');
let fs = require('fs');
let path = require('path');

// Đọc RSA keys (RS256 - 2048 bits)
let PRIVATE_KEY = fs.readFileSync(path.join(__dirname, '..', 'private.pem'), 'utf8');
let PUBLIC_KEY = fs.readFileSync(path.join(__dirname, '..', 'public.pem'), 'utf8');

module.exports = {
    // Tạo JWT token bằng thuật toán RS256
    generateToken: function (userData) {
        return jwt.sign(
            {
                id: userData._id,
                username: userData.username,
                email: userData.email,
                role: userData.role
            },
            PRIVATE_KEY,
            {
                algorithm: 'RS256',
                expiresIn: '1h'
            }
        );
    },

    // Middleware xác thực token
    verifyToken: function (req, res, next) {
        try {
            let authHeader = req.headers['authorization'];
            if (!authHeader) {
                return res.status(401).send({
                    message: "Token khong duoc cung cap"
                });
            }

            // Lấy token từ header "Bearer <token>"
            let token = authHeader.split(' ')[1];
            if (!token) {
                return res.status(401).send({
                    message: "Token khong hop le"
                });
            }

            // Xác thực token bằng public key (RS256)
            let decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
            req.user = decoded;
            next();
        } catch (error) {
            return res.status(401).send({
                message: "Token het han hoac khong hop le"
            });
        }
    }
};
