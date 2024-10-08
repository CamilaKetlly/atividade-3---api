/* imports */
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// Config JSON response
app.use(express.json())

// Models
const User = require('./models/User')

// Open Route - Public Rout
app.get('/', (req, res) => {
    res.status(200).json({msg: 'Bem vindo a nossa API!' })
})

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {

    const id = req.params.id

// check if user exists
const user = await User.findById(id, '-password')

if(!user) {
    return res.status(404).json({ msg: 'Não te encontramos, não...'}) 
}

res.status(200).json({ user })
})

function checkToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({msg: 'Pode entrar não.'})
    }

try {

    const secret = process.env.SECRET

    jwt.verify(token, secret)

    next()
} catch(error) {
    res.status(400).json({msg: 'Token Inválido'})
}

}

// Register User
app.post('/auth/register', async(req, res) => {

const {name, email, password, confirmpassword} = req.body

// validations
if(!name) {
    return res.status(422).json({msg: 'O nome é obrigatório!'})
}
if(!email) {
    return res.status(422).json({msg: 'O email é obrigatório, tá ligado?!'})
}
if(!password) {
    return res.status(422).json({msg: 'Oxe, a senha é obrigatória!'})
}
if(!password !== confirmpassword) {
    return res.status(422).json({msg: 'Se liga, as senhas não conferem!'})
}

// check if user exists
const userExists = await User.findOne({ email: email })

if(userExists) {
    return res.status(422).json({msg: 'Utilize outro email, cumpaça!'})
}

// create password
const salt = await bcrypt.genSalt(12)
const passwordHash = await bcrypt.hash(password, salt)

// create user
const user = new User ({
    name,
    email,
    password: passwordHash,
})

try {

    await user.save()

    res.status(201). json({ msg: 'Usuário criado, ufa!'})

} catch(error) {
    console.log(error)

    res.status(500).json({msg: 'Aconteceu um erro, visse. Tenta de novo já já!'})
}
})

// Login User
app.post('/auth/login', async (req, res) => {

const {email, password} = req.body

// validations
if(!email) {
    return res.status(422).json({msg: 'O email é obrigatório, tá ligado?!'})
}
if(!password) {
    return res.status(422).json({msg: 'Oxe, a senha é obrigatória!'})
}

// check if user exists
const user = await User.findOne({ email: email })

if(!user) {
    return res.status(404).json({msg: 'Usuário não encontrado, cumpaça!'})
}

// check if password match
const checkPassword = await bcrypt.compare(password, user.password)

if(!checkPassword) {
    return res.status(422).json({msg: 'Ixi, senha inválida!'})
}

try {

    const secret = process.env.SECRET

    const token = jwt.sign({
        id: user._id,

    },
secret,
)

res.status(200).json({msg: 'Boa, véi. Logasse!', token })
} catch(err) {

    console.log(error)

    res.status(500).json({msg: 'Aconteceu um erro, visse. Tente novamente depois!'})

}

})

// Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect('mongodb+srv://${dbUser}:${dbPassword}@cluster0.zqzo6.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'

).then(() =>{
    app.listen(3000)
    console.log('Conectou ao banco!')
}).catch((err) => console.log(err))

