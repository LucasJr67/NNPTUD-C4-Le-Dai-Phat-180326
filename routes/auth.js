let express = require('express');
let router = express.Router()
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
let { generateToken, verifyToken } = require('../utils/authHandler')
let { ChangePasswordValidator, validatedResult } = require('../utils/validator')

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(username, password, email,
            "69b1265c33c5468d1c85aad8"
        )
        res.send(newUser)
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})

router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) {
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
            return;
        }
        if (user.lockTime > Date.now()) {
            res.status(404).send({
                message: "ban dang bi ban"
            })
            return;
        }
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save()
            // Tạo JWT token bằng RS256
            let token = generateToken(user);
            res.send({
                id: user._id,
                token: token
            })
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000;
            }
            await user.save()
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
        }
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})

// GET /me - Lấy thông tin người dùng hiện tại (yêu cầu đăng nhập)
router.get('/me', verifyToken, async function (req, res, next) {
    try {
        let user = await userController.GetAnUserById(req.user.id);
        if (!user) {
            return res.status(404).send({
                message: "Nguoi dung khong ton tai"
            })
        }
        res.send({
            id: user._id,
            username: user.username,
            email: user.email,
            fullName: user.fullName,
            avatarUrl: user.avatarUrl,
            status: user.status,
            role: user.role,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        })
    } catch (error) {
        res.status(500).send({
            message: error.message
        })
    }
})

// POST /changepassword - Đổi mật khẩu (yêu cầu đăng nhập)
router.post('/changepassword', verifyToken, ChangePasswordValidator, validatedResult, async function (req, res, next) {
    try {
        let { oldPassword, newPassword } = req.body;

        // Lấy thông tin user từ token
        let user = await userController.GetAnUserById(req.user.id);
        if (!user) {
            return res.status(404).send({
                message: "Nguoi dung khong ton tai"
            })
        }

        // Kiểm tra mật khẩu cũ có đúng không
        if (!bcrypt.compareSync(oldPassword, user.password)) {
            return res.status(400).send({
                message: "Mat khau cu khong dung"
            })
        }

        // Kiểm tra mật khẩu mới không được trùng mật khẩu cũ
        if (bcrypt.compareSync(newPassword, user.password)) {
            return res.status(400).send({
                message: "Mat khau moi khong duoc trung voi mat khau cu"
            })
        }

        // Cập nhật mật khẩu mới
        user.password = newPassword;
        await user.save();

        res.send({
            message: "Doi mat khau thanh cong"
        })
    } catch (error) {
        res.status(500).send({
            message: error.message
        })
    }
})

module.exports = router