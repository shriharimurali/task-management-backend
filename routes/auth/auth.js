const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const User = require('../../model/user');

const Yup = require('yup');
const authenticateToken = require('../../middleware/authenticateToken');

const registerSchema = Yup.object({
  fname: Yup.string().min(3).required(),
  lname: Yup.string().min(3).required(),
  email: Yup.string().min(6).email().required(),
  password: Yup.string().min(8).required(),
});

// Register Route

router.post('/register', async (req, res) => {
  const { fname, lname, email, password } = req.body;
  const emailExist = await User.findOne({ email });

  if (emailExist) {
    return res.status(400).send('Email already exists.');
  }

  const salt = await bcrypt.genSaltSync(10);
  const hashPassword = await bcrypt.hash(password, salt);

  const user = new User({
    fname,
    lname,
    email,
    password: hashPassword,
  });

  try {
    const { error } = await registerSchema.validateSync(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    await user.save();
    return res.status(200).send('User create successfully!.');
  } catch (error) {
    res.status(500).send(error);
  }
});

const loginSchema = Yup.object({
  email: Yup.string().min(6).required().email(),
  password: Yup.string().min(6).required(),
});

// Login Route

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    return res.status(400).send('User do not exists. Please Sign up');
  }

  const validPassword = await bcrypt.compare(password, user.password);

  if (!validPassword) {
    return res.status(400).send('Invalid Password');
  }

  try {
    const { error } = await loginSchema.validateSync(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const accessToken = generateAccessToken({ id: user.id });
    const refreshToken = generateRefreshToken({ id: user.id });

    res.json({ accessToken, refreshToken, user: { ...getBasicDetails(user) } });
  } catch (error) {
    res.status(500).send(error);
  }
});

function getBasicDetails(user) {
  const { id, fname, lname, email } = user;
  return { id, fname, lname, email };
}

router.post('/refresh', (req, res) => {
  const refreshToken = req.body.refreshToken;

  if (refreshToken == null) return res.sendStatus(401, 'Unauthorized!');
  jwt.verify(refreshToken, process.env.JWT_REFRESH_KEY, (err, user) => {
    if (err) return res.sendStatus(401).send(err);
    const accessToken = generateAccessToken({ id: user.id });
    const refreshToken = generateRefreshToken({ id: user.id });
    res.json({ accessToken, refreshToken });
  });
});

function generateAccessToken(user) {
  return jwt.sign({ id: user.id }, process.env.JWT_KEY, {
    expiresIn: process.env.EXPIRES_IN,
    algorithm: process.env.ALGO_CONFIG,
  });
}

function generateRefreshToken(user) {
  return jwt.sign({ id: user.id }, process.env.JWT_REFRESH_KEY, {
    expiresIn: process.env.REFRESH_EXPIRES_IN,
    algorithm: process.env.ALGO_CONFIG,
  });
}

router.get('/userInfo', async (req, res) => {
  const token = req.headers.authorization;

  if (token) {
    const decoded = jwt.decode(token?.split(' ')[1]);
    const user = await User.findOne({ _id: decoded.id });
    res.json({ fname: user.fname, lname: user.lname, email: user.email });
  } else {
    res.status(401).send('Unauthorized!');
  }
});

module.exports = router;
