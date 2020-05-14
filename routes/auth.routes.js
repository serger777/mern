const { Router } = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const {check, validationResult } = require('express-validator');
const router = Router();

const User = require('../models/User');

router.post(
    '/register',
    [
        check('email', 'email некорректный').isEmail(),
        check('password', 'минимальная длинна паролья 6 символов')
            .isLength({min:3})
    ],
    async (req, res)=>{
        try {
           const errors = validationResult(req);
            if(!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'некорректные данные регистрации'
            })
        }
        const { email, password } = req.body;
        const candidate = await User.findOne({ email });
        if(candidate){
            res.status(400).json({message: 'такой пользователь существует'})
        }
     const hashedPassword = await bcrypt.hash(password, 12 );

     const user = new User({email, password: hashedPassword });

     await user.save();

     res.status(201).json({message: 'Пользователь создан'});

    } catch (e) {
            res.status(500).json({message: 'что то пошло не так'})
    }
});
router.post(
    '/login',
    [
        check('email', 'введите корректный email').normalizeEmail().isEmail(),
        check('password', 'введите пароль').exists()
    ],
    async (req, res)=>{
        try {
            console.log(req.body);
            const errors = validationResult(req);
            if(!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'некорректные данные при входе в систему'
                })
            }
            const {email, password}= req.body;
            const user = await User.findOne({ email });
            if(!user){
                return res.status(400).json({message: 'пользователь не найден'})
            }
            const isMatch = await bcrypt.compare(password, user.password);
            if(!isMatch){
                return res.status(400).json({message: 'неверный пароль'})
            }
            const token =jwt.sign(
                {userId: user.id},
                config.get('jwtSecret'),
                {expiresIn: '1h'}
                );
            res.json({token, userId:user.id})
        } catch (e) {
            console.log(e);
            res.status(500).json({message: 'что то пошло не так'})
        }
});
module.exports = router;