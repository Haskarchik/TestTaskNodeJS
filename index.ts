const express = require('express');
const bcrypt = require('bcryptjs');
const Joi = require('joi');
const app = express();
const port = 3000;

import { Request, Response } from 'express';

interface UserDto {
  username: string;
  email: string;
  type: 'user' | 'admin';
  password: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

// Database mock where the username is the primary key of a user.
const MEMORY_DB: Record<string, UserEntry> = {};

// Helper functions to query the memory db
function getUserByUsername(name: string): UserEntry | undefined {
  return MEMORY_DB[name];
}

function getUserByEmail(email: string): UserEntry | undefined {
  // Find the user entry where the email matches
  const username = Object.keys(MEMORY_DB).find(
    (key) => MEMORY_DB[key].email === email
  );
  return username ? MEMORY_DB[username] : undefined;
}

// Middleware for parsing JSON request body.
app.use(express.json());

// Validation schema for user registration
const userSchema = Joi.object({
  username: Joi.string().min(3).max(24).required(),
  email: Joi.string().email().required(),
  type: Joi.string().valid('user', 'admin').required(),
  password: Joi.string()
    .min(5)
    .max(24)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/)
    .required()
    .messages({
      'string.pattern.base':
        'Password must contain uppercase, lowercase, and at least one special character',
    }),
});

// Request body -> UserDto
app.post('/register', (req: Request, res: Response) => {
  // Validate user object using joi
  const validation = userSchema.validate(req.body);
  if (validation.error) {
    return res.status(400).json({ error: validation.error.details[0].message });
  }

  const userDto: UserDto = req.body;

  // Check if username already exists
  if (getUserByUsername(userDto.username)) {
    return res.status(409).json({ error: 'Username already exists' });
  }

  // Check if email already exists
  if (getUserByEmail(userDto.email)) {
    return res.status(409).json({ error: 'Email already exists' });
  }

  // Create salt and hash the password
  const salt = bcrypt.genSaltSync(10);
  const passwordhash = bcrypt.hashSync(userDto.password, salt);

  // Save user to memory database
  MEMORY_DB[userDto.username] = {
    email: userDto.email,
    type: userDto.type,
    salt,
    passwordhash,
  };

  return res.status(201).json({ message: 'User registered successfully' });
});

// Request body -> { username: string, password: string }
app.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  // Check if required fields are provided
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'Username and password are required' });
  }

  // Get user from database
  const user = getUserByUsername(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Verify password
  const passwordMatches = bcrypt.compareSync(password, user.passwordhash);
  if (!passwordMatches) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Return successful login response
  return res.status(200).json({
    message: 'Login successful',
    user: {
      username,
      email: user.email,
      type: user.type,
    },
  });
});

app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`);
});
