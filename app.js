require('dotenv').config()

process.on('unhandledRejection', (reason, p) => {
  console.log('Unhandled Rejection at: Promise', p, 'reason:', reason)
  // application specific logging, throwing an error, or other logic here
})

process.on('uncaughtException', function (exception) {
  console.log(exception)
  // handle or ignore error
})

const express = require('express') //
const bodyParser = require('body-parser')
const mongoose = require('mongoose') // db access driver for mongodb
const bcrypt = require('bcryptjs') // hashed passwords for storage
const session = require('express-session') // login and auth sessions
const crypto = require('crypto') //
const jwt = require('jsonwebtoken') //
const cookieParser = require('cookie-parser')
const cors = require('cors') // cross orgin access to resources recieved/sent by server
const morgan = require('morgan')
const winston = require('winston')
const { spawn } = require('child_process')

const app = express()

// setting up winston and morgan
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'user-service' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
})

// If we're not in production we're gonna also log to the `console`
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }))
}

// setting up morgan
morgan.token('id', function getId (req) {
  return req.id
})

app.use(cors()) // Add this line before defining routes
app.use(bodyParser.json())
app.use(cookieParser())
app.use(morgan(':id :status :method :url :response-time')) // using morgan to log http requests
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

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
    res.status(401).json({ error: 'Unauthorised: Please Log in' })
  }
}
const { Schema } = mongoose
mongoose.connect(process.env.MONGO_CONNECTION_STRING, {
  useNewUrlParser: true,
  useUnifiedTopology: true

})

const userSchema = new Schema({
  name: { type: String, require: true },
  username: { type: String, require: true },
  password: { type: String, require: true },
  isVerified: { type: Boolean, default: false },
  tokenVersion: { type: Number, default: 0 }
})

const productSchema = new Schema({
  _id: { type: String },
  barcode: { type: String, require: true },
  name: { type: String, require: true }
})

const FridgeSchema = new Schema({
  item: { type: String, require: true },
  owner: { type: String, require: true },
  expiry: { type: Date, require: true },
  dateAdded: { type: Date, require: true }

})

const UserVerificationCodeSchema = new Schema({

  owner: { type: String, require: true },
  code: { type: String, require: true },
  dateCreated: { type: Date, default: Date.now },
  expiry: { type: String, require: true }

})

const Fridge = mongoose.model('Fridge', FridgeSchema)
const User = mongoose.model('User', userSchema)
const Product = mongoose.model('Product', productSchema)
const UserVerificationCode = mongoose.model('UserVerificationCode', UserVerificationCodeSchema)

async function generateUniqueProductId (barcode) {
  let id
  let existingProductById
  let existingProductByBarcode

  do {
    // Generate random 11-digit number
    id = Math.floor(10000000000 + Math.random() * 90000000000).toString()

    // Check if a product with this id already exists
    existingProductById = await Product.findOne({ _id: id })

    // Check if a product with this barcode already exists
    existingProductByBarcode = await Product.findOne({ barcode })

    if (existingProductById) {
      return { error: 'Product with this ID already exists.' }
    }

    if (existingProductByBarcode) {
      return { error: 'Product with this barcode already exists.' }
    }
  } while (existingProductById != null || existingProductByBarcode != null)

  return id
}

app.post('/api/register', async (req, res) => {
  const { name, username, password } = req.body

  if (name === undefined || username === undefined || password === undefined) return res.status(400).json({ error: 'Incomplete Data Entry' })

  const existingUser = await User.findOne({ username })
  if (existingUser) {
    return res.status(400).json({ error: 'User already exists' })
  }

  const salt = bcrypt.genSaltSync(10)
  const hashedPassword = bcrypt.hashSync(password + process.env.PEPPER, salt)

  const user = new User({ name, username, password: hashedPassword })
  await user.save()

  const pythonScriptPath = 'sendMessage.py'
  const recipient_number = 447784459499
  const python = spawn('python3', [pythonScriptPath, recipient_number])
  python.stdout.on('data', async function (data) {
    console.log('Pipe data from python script ...')
    const extractedNumber = data ? data.toString().replace(/\D/g, '') : ''
    console.log('Extracted verification number from python script ...')
    const newUserVerificationCode = new UserVerificationCode({
      owner: username,
      code: extractedNumber,
      dateCreated: new Date().toISOString(),
      expiry: new Date(new Date().setMinutes(new Date().getMinutes() + 10)).toISOString() // setting the expiry to 10 minutes from now.
    })
    try {
      await newUserVerificationCode.save()
      console.log('User verification code saved successfully!')
    } catch (err) {
      console.log(err)
    }
  })
  python.stderr.on('data', (data) => {
    // handle error data here
    console.log(`stderr: ${data}`)
  })
  python.on('close', (code) => {
    console.log(`child process exited with code ${code}`)
  })

  res.status(200).json({ message: 'User registered successfully', username })
})

app.post('/api/userVerificationCode', requireAuth, (req, res) => {
  const username = req.body.username
  const verificationcode = req.body.verificationcode

  if (!username || !verificationcode) {
    return res.status(400).json({ error: 'Username and verification code are required' })
  }

  UserVerificationCode.find({ owner: username })
    .then(entries => {
      if (entries) {
        let isCodeMatching = false
        entries.forEach(entry => {
          if (entry.code === verificationcode) {
            isCodeMatching = true
          }
        })
        if (isCodeMatching) {
          res.status(200).json({ status: 'Verification code matches' })
        } else {
          res.status(401).json({ status: 'Verification code does not match' })
        }
      } else {
        res.status(404).json({ error: 'Entries not found' })
      }
    })
    .catch(err => {
      console.error(err)
      res.status(500).json({ error: 'Server error' })
    })
})

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body
  const user = await User.findOne({ username })
  if (!user) {
    return res.status(401).json({ error: 'Invalid username' })
  }

  const validPassword = await bcrypt.compare(password + process.env.PEPPER, user.password)
  if (!validPassword) {
    return res.status(401).json({ error: 'Invalid password' })
  }

  const token = jwt.sign({ username, tokenVersion: user.tokenVersion }, sessionSecret, { expiresIn: '1h' })

  res.json({ message: 'Login successful', token, user: user.name, username })
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
    res.json({ name: user.name, username: user.username, isVerified: user.isVerified })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/change-password', requireAuth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: 'Missing required fields' })
    }

    const token = req.headers.authorization.split(' ')[1]
    const { username } = jwt.verify(token, sessionSecret)
    const user = await User.findOne({ username })

    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }

    const validPassword = await bcrypt.compare(oldPassword + process.env.PEPPER, user.password)
    if (!validPassword) {
      return res.status(401).json({ error: 'Old password is incorrect' })
    }

    const salt = bcrypt.genSaltSync(10)
    const hashedNewPassword = bcrypt.hashSync(newPassword + process.env.PEPPER, salt)
    user.password = hashedNewPassword
    user.tokenVersion += 1 // Invalidate all old tokens

    await user.save()

    res.json({ message: 'Password updated successfully' })
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

// Create a new fridge item
app.post('/api/user-add-fridge-item', requireAuth, async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1]
    const { username } = jwt.verify(token, sessionSecret)
    const { item, expiry } = req.body

    let expiryDate = expiry
    if (!expiryDate) {
      expiryDate = new Date('2000-01-01T00:00:01')
    }
    const newFridgeItem = new Fridge({
      item,
      owner: username,
      expiry: expiryDate
    })

    const savedFridgeItem = await newFridgeItem.save()

    res.status(201).json({ message: 'Fridge item added successfully', data: savedFridgeItem })
  } catch (error) {
    res.status(500).json({ error: 'Internal server error', message: error.message })
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
// Catalogue methods
app.get('/api/products', requireAuth, async (req, res) => {
  try {
    const products = await Product.find()
    console.log(products)
    res.json(products)
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/add-to-catalogue', requireAuth, async (req, res) => {
  try {
    const { barcode, name } = req.body

    if (barcode === undefined || name === undefined) {
      console.log('Incomplete data entry, missing barcode or name')
      return res.status(400).json({ error: 'Incomplete Data Entry' })
    }
    const newid = await generateUniqueProductId(barcode)
    const product = new Product({ _id: newid, barcode, name })
    await product.save()
    console.log('Product saved successfully')

    res.status(200).json({ message: 'Product added successfully', _id: product._id })
  } catch (error) {
    console.error('Internal server error: ', error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.post('/api/edit-product', requireAuth, async (req, res) => {
  try {
    const { _id, name, barcode } = req.body

    if (!_id || !name || !barcode) {
      return res.status(400).json({ error: 'Incomplete Data Entry' })
    }

    const product = await Product.findOneAndUpdate({ _id }, { name, barcode }, { new: true })

    if (!product) {
      return res.status(404).json({ error: 'Product not found' })
    }

    res.status(200).json({ message: 'Product updated successfully', product })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.delete('/api/catalogue-delete-product', requireAuth, async (req, res) => {
  try {
    const { barcode } = req.body

    if (!barcode) { return res.status(400).json({ error: 'Incomplete Data Entry' }) }

    const product = await Product.findOneAndDelete({ barcode })

    if (!product) { return res.status(404).json({ error: 'Product not found' }) }

    res.status(200).json({ message: 'Product deleted successfully' })
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

app.post('/api/delete-user', requireAuth, async (req, res) => {
  const token = req.headers.authorization.split(' ')[1]
  const { username } = jwt.verify(token, sessionSecret)

  // Validate the request body
  if (!username) {
    return res.status(400).send('Username is required')
  }

  try {
    // Remove the user from the database
    const result = await User.findOneAndDelete({ username })
    // delete rest of owner stuff from tables
    if (!result) {
      return res.status(404).send('User not found')
    }

    return res.status(200).send('User deleted')
  } catch (err) {
    console.error(err)
    return res.status(500).send('Server error')
  }
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

const port = process.env.PORT || 8080
app.listen(port, () => {
  winston.info(`HTTP Server listening on port ${port}`)
})
