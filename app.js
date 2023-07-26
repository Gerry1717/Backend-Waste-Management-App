require('dotenv').config()

const express = require('express')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const session = require('express-session')
const https = require('https')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const cors = require('cors') // Add this line

const sslCertsPath = path.join(__dirname, 'sslcerts')

const app = express()

app.use(cors()) // Add this line before defining routes
app.use(bodyParser.json())
app.use(cookieParser())

const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex')

app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 600000,
      httpOnly: true
    }
  })
)

const requireAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1]
    const { username, tokenVersion } = jwt.verify(token, sessionSecret)

    const user = await User.findOne({ username })
    if (user.tokenVersion !== tokenVersion) {
      return res.status(401).json({ error: 'Token is no longer valid, please log in again' })
    }

    next()
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized' })
  }
}
const { Schema } = mongoose
mongoose.connect(process.env.MONGO_CONNECTION_STRING, {
  useNewUrlParser: true,
  useUnifiedTopology: true

})

const userSchema = new Schema({
  name: String,
  username: String,
  password: String,
  pepper: String,
  tokenVersion: { type: Number, default: 0 }
})

const productSchema = new Schema({
  barcode: String,
  name: String
})

const FridgeSchema = new Schema({
  item: String,
  owner: String,
  expiry: Date

})

const Fridge = mongoose.model('Fridge', FridgeSchema)
const User = mongoose.model('User', userSchema)
const Product = mongoose.model('Product', productSchema)

app.post('/api/register', async (req, res) => {
  const { name, username, password } = req.body

  const existingUser = await User.findOne({ username })
  if (existingUser) {
    return res.status(400).json({ error: 'User already exists' })
  }

  const pepper = crypto.randomBytes(16).toString('hex')
  const hashedPassword = await bcrypt.hash(password + pepper, 10)

  const user = new User({ name, username, password: hashedPassword, pepper })
  await user.save()

  res.status(200).json({ message: 'User registered successfully', username })
})

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body
  const user = await User.findOne({ username })
  if (!user) {
    return res.status(401).json({ error: 'Invalid username' })
  }

  const validPassword = await bcrypt.compare(password + user.pepper, user.password)
  if (!validPassword) {
    return res.status(401).json({ error: 'Invalid password' })
  }

  const token = jwt.sign({ username, tokenVersion: user.tokenVersion }, sessionSecret, { expiresIn: '1h' })
  res.json({ message: 'Login successful', token, username })
})

app.get('/api/user-details', requireAuth, async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1]
    const { username } = jwt.verify(token, sessionSecret)

    const user = await User.findOne({ username })

    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }

    // Return the user's name and username
    res.json({ name: user.name, username: user.username })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.get('/api/user-fridge-items', requireAuth, async (req, res) => {
  const token = req.headers.authorization.split(' ')[1]
  const { username } = jwt.verify(token, sessionSecret)

  const user = await User.findOne({ username })

  if (!user) {
    return res.status(404).json({ error: 'User not found' })
  }

  try {
    const fridges = await Fridge.find({ owner: username })
      .populate('item')
      .populate('expiry')
      .exec()

    res.json(fridges)
  } catch (err) {
    res.status(500).json({ error: err })
  }
})

app.post('/api/user-add-to-fridge', requireAuth, async (req, res) => {
  try {
    const { barcode } = req.body
    const product = await Product.findOne({ barcode })

    if (!product) {
      return res.status(404).json({ error: 'Product not found' })
    }

    const expiry = '01/01/2000'

    const token = req.headers.authorization.split(' ')[1]
    const { username } = jwt.verify(token, sessionSecret)

    const user = await User.findOne({ username })

    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }

    const newItem = new Fridge({ item: product.barcode, owner: username, expiry })
    await newItem.save()
    console.log(newItem)

    res.json({ message: 'Item added successfully' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})
app.post('/api/update-expiry', requireAuth, async (req, res) => {
  const { barcode, newExpiry } = req.body

  try {
    const token = req.headers.authorization.split(' ')[1]
    const { username } = jwt.verify(token, sessionSecret)

    const user = await User.findOne({ username })

    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }

    const product = await Product.findOne({ barcode })

    if (!product) {
      return res.status(404).json({ error: 'Product not found' })
    }

    const fridgeItem = await Fridge.findOne({ item: product.barcode, owner: username })

    if (!fridgeItem) {
      return res.status(404).json({ error: 'Product not found in user fridge' })
    }

    fridgeItem.expiry = newExpiry
    await fridgeItem.save()

    res.json({ message: 'Expiry date updated successfully' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.get('/api/products', requireAuth, async (req, res) => {
  try {
    const products = await Product.find()
    res.json(products)
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.get('/api/userAuth', requireAuth, async (req, res) => {
  try {
    res.json({ message: 'true' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/logout', requireAuth, async (req, res) => {
  const token = req.headers.authorization.split(' ')[1]
  const { username } = jwt.verify(token, sessionSecret)

  await User.updateOne({ username }, { $inc: { tokenVersion: 1 } })

  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Could not log out, please try again' })
    }

    res.clearCookie('token')
    res.json({ message: 'Successfully logged out' })
  })
})

app.delete('/api/user-remove-from-fridge', requireAuth, async (req, res) => {
  try {
    const { barcode } = req.body
    const token = req.headers.authorization.split(' ')[1]
    const { username } = jwt.verify(token, sessionSecret)

    const user = await User.findOne({ username })

    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }

    const result = await Fridge.deleteOne({ item: barcode, owner: username })

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Item not found in the fridge' })
    }

    res.json({ message: 'Item removed from the fridge successfully' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.delete('/api/user-clear-fridge', requireAuth, async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1]
    const { username } = jwt.verify(token, sessionSecret)

    const user = await User.findOne({ username })

    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }

    await Fridge.deleteMany({ owner: username })

    res.json({ message: 'Fridge cleared successfully' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.use((req, res, next) => {
  res.status(404).json({ error: 'Resource not found' })
})

app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).json({ error: 'Internal server error' })
})

const httpsOptions = {
  key: fs.readFileSync(path.join(sslCertsPath, 'server.key')),
  cert: fs.readFileSync(path.join(sslCertsPath, 'server.crt'))
}

https.createServer(httpsOptions, app).listen(443, () => {
  console.log('Server listening on port 443')
})
