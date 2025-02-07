// server.js (updated with more API routes)
require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

const serviceAccount = JSON.parse(process.env.SERVICE_KEY);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = admin.database();

const jwtSecret = process.env.JWT_SECRET || 'your-default-secret';
const ayeTStudiosApiKey = process.env.AYET_API_KEY;
const coinsToDollarRatio = 100;

function generateToken(payload) {
    return jwt.sign(payload, jwtSecret, { expiresIn: '1h' });
}

// --------------------------------------------------------------------
//  User Authentication Routes (same as before)
// --------------------------------------------------------------------
app.post('/register', async (req, res) => {
    // ... (Registration route - same as before)
    try {
        const { email, username, password } = req.body;

        // Basic validation (add more robust validation as needed)
        if (!email || !username || !password) {
            return res.status(400).json({ message: 'Missing required fields.' });
        }

        // Check if user already exists (email or username)
        const usersRef = db.ref('users');
        const snapshotEmail = await usersRef.orderByChild('email').equalTo(email).once('value');
        const snapshotUsername = await usersRef.orderByChild('username').equalTo(username).once('value');

        if (snapshotEmail.exists()) {
            return res.status(400).json({ message: 'Email already registered.' });
        }

        if (snapshotUsername.exists()) {
            return res.status(400).json({ message: 'Username already taken.' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create the user in Firebase Realtime Database
        const newUser = {
            email,
            username,
            password: hashedPassword,
            coins: 0, // Initial coin balance
            referralCode: generateReferralCode() // Function to generate a unique referral code
        };

        const newUserRef = await usersRef.push(newUser); // Use push() to generate a unique ID

        // Generate JWT token
        const token = generateToken({ userId: newUserRef.key, username: username }); // Use the generated key as the userId

        res.status(201).json({ message: 'User registered successfully.', token: token, userId: newUserRef.key }); // Return the userId as well.
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Registration failed.', error: error.message });
    }
});
app.post('/login', async (req, res) => {
    // ... (Login route - same as before)
    try {
        const { email, password } = req.body;

        // Basic validation
        if (!email || !password) {
            return res.status(400).json({ message: 'Missing email or password.' });
        }

        // Find the user by email
        const usersRef = db.ref('users');
        const snapshot = await usersRef.orderByChild('email').equalTo(email).once('value');

        if (!snapshot.exists()) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        let userId = null;
        let user = null;

        snapshot.forEach((childSnapshot) => {
            userId = childSnapshot.key;
            user = childSnapshot.val();
        });

        // Verify password
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Generate JWT token
        const token = generateToken({ userId: userId, username: user.username }); // Use the userId from Firebase

        res.status(200).json({ message: 'Login successful.', token: token, userId: userId });  //Return userId
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Login failed.', error: error.message });
    }
});
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

    if (!token) {
        return res.status(401).json({ message: 'Authentication required.' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            console.error("Token verification error:", err);
            return res.status(403).json({ message: 'Invalid token.' });
        }

        req.user = user; // Add user info to the request object
        next(); // Pass control to the next middleware/route handler
    });
}
app.get('/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;  // Extract the user ID from the JWT payload

        // Fetch user data from Firebase
        const userRef = db.ref(`users/${userId}`);
        const snapshot = await userRef.once('value');
        const user = snapshot.val();

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // Return user profile data (omit sensitive information like password hash)
        const profile = {
            username: user.username,
            email: user.email,
            coins: user.coins,
            referralCode: user.referralCode
            // Add other profile information as needed
        };

        res.status(200).json(profile);

    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ message: 'Failed to retrieve profile.', error: error.message });
    }
});

// --------------------------------------------------------------------
//  ayeT-Studios Integration (Callbacks) (same as before)
// --------------------------------------------------------------------
app.post('/ayet-callback', async (req, res) => {
    // ... (ayeT callback route - same as before)
    try {
        const { external_identifier, payout, transaction_id, sig } = req.body;

        // Basic validation of callback data
        if (!external_identifier || !payout || !transaction_id || !sig) {
            console.warn("Invalid ayeT callback: Missing parameters");
            return res.status(400).send('Invalid parameters');
        }

        // ** IMPORTANT:  Signature Verification **
        //  You MUST verify the signature to prevent fraud.
        //  See ayeT-Studios documentation for signature calculation.
        const receivedSig = req.headers['x-ayetstudios-security-hash'];
        if (!receivedSig) {
            console.error("Invalid ayeT callback: Missing X-Ayetstudios-Security-Hash header");
            return res.status(403).send('Missing signature header');
        }

        const expectedSig = calculateHMACSignature(req.body, ayeTStudiosApiKey);

        if (receivedSig !== expectedSig) {
            console.error("Invalid ayeT callback: Invalid signature");
            return res.status(403).send('Invalid signature');  // Or 403 Forbidden
        }

        // Find the user by their external_identifier (assuming it's the same as your user ID)
        const userId = external_identifier;
        const userRef = db.ref(`users/${userId}`);
        const snapshot = await userRef.once('value');
        const user = snapshot.val();

        if (!user) {
            console.warn(`ayeT callback: User not found with ID ${userId}`);
            return res.status(404).send('User not found'); // Or handle as appropriate
        }

        // Credit the user with the payout
        const coinsToAdd = Math.round(parseFloat(payout) * coinsToDollarRatio);  //Pout is payout amount in $

        await userRef.update({
            coins: user.coins + coinsToAdd
        });

        console.log(`Credited user ${userId} with ${coinsToAdd} coins from ayeT transaction ${transaction_id}`);
        res.status(200).send('OK'); // Respond to ayeT-Studios with 200 OK.  THIS IS IMPORTANT.

    } catch (error) {
        console.error("Error processing ayeT callback:", error);
        res.status(500).send('Internal Server Error');
    }
});

// --------------------------------------------------------------------
//  Other API Routes (Dashboard Features)
// --------------------------------------------------------------------
app.post('/withdrawal', authenticateToken, async (req, res) => {
    // ... (Withdrawal route - same as before)
    try {
        const userId = req.user.userId;
        const { amount, paymentMethod, paymentDetails } = req.body; // Example: { amount: 100, paymentMethod: 'skrill', paymentDetails: { email: 'user@example.com' } }

        // Input validation
        if (!amount || !paymentMethod || !paymentDetails) {
            return res.status(400).json({ message: 'Missing withdrawal information.' });
        }

        const amountInDollars = parseFloat(amount);
        if (isNaN(amountInDollars) || amountInDollars <= 0) {
            return res.status(400).json({ message: 'Invalid withdrawal amount.' });
        }

        // Get the user's current coin balance
        const userRef = db.ref(`users/${userId}`);
        const snapshot = await userRef.once('value');
        const user = snapshot.val();

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const coinsToWithdraw = Math.round(amountInDollars * coinsToDollarRatio);

        if (user.coins < coinsToWithdraw) {
            return res.status(400).json({ message: 'Insufficient coins.' });
        }

        if (amountInDollars < 100) {
            return res.status(400).json({ message: 'Minimum Payout is $100' });
        }


        // Create a withdrawal request in Firebase
        const withdrawalsRef = db.ref('withdrawals');
        const newWithdrawal = {
            userId: userId,
            amount: amountInDollars, // Store in USD
            coins: coinsToWithdraw,
            paymentMethod: paymentMethod,
            paymentDetails: paymentDetails,
            status: 'pending', //  pending, processing, completed, rejected
            requestDate: new Date().toISOString()
        };

        await withdrawalsRef.push(newWithdrawal);

        // Deduct coins from the user's balance (immediately, or after admin approval - your choice)
        await userRef.update({
            coins: user.coins - coinsToWithdraw
        });

        res.status(201).json({ message: 'Withdrawal request submitted successfully.' });

    } catch (error) {
        console.error('Withdrawal error:', error);
        res.status(500).json({ message: 'Failed to submit withdrawal request.', error: error.message });
    }
});

// Tasks (Example: Fetch a list of available tasks)
app.get('/tasks', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        // Fetch tasks from Firebase (replace with your actual data structure)
        const tasksRef = db.ref('tasks');
        const snapshot = await tasksRef.once('value');
        const tasks = snapshot.val();

        if (!tasks) {
            return res.status(404).json({ message: 'No tasks found.' });
        }

        // Get user's completed tasks (replace with your actual data structure)
        const userTasksRef = db.ref(`user_tasks/${userId}`);  // Assuming you store completed tasks separately
        const userTasksSnapshot = await userTasksRef.once('value');
        const userTasks = userTasksSnapshot.val() || {};  // Default to empty object if no user tasks

        //Mark completed tasks
        const availableTasks = Object.entries(tasks).map(([taskId, task]) => {
            const completed = userTasks[taskId] ? true : false;
            return { ...task, id: taskId, completed: completed };
        });

        res.status(200).json(availableTasks);

    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ message: 'Failed to retrieve tasks.', error: error.message });
    }
});

// Spin and Win (Example: Handle a spin request)
app.post('/spin', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        //  Implement your spin logic here (e.g., generate a random reward)
        const reward = generateSpinReward();

        // Credit the user with the reward
        const userRef = db.ref(`users/${userId}`);
        const snapshot = await userRef.once('value');
        const user = snapshot.val();

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        await userRef.update({
            coins: user.coins + reward.coins
        });

        res.status(200).json({ message: 'Spin successful.', reward: reward });

    } catch (error) {
        console.error('Error spinning:', error);
        res.status(500).json({ message: 'Spin failed.', error: error.message });
    }
});

// Referrals (Example: Get user's referral stats)
app.get('/referrals', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        // Get user's referral code from their profile
        const userRef = db.ref(`users/${userId}`);
        const snapshot = await userRef.once('value');
        const user = snapshot.val();

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const referralCode = user.referralCode;

        // Find all users who used this referral code (replace with your actual data structure)
        const referredUsersRef = db.ref('users').orderByChild('referredBy').equalTo(referralCode);
        const referredUsersSnapshot = await referredUsersRef.once('value');
        const referredUsers = referredUsersSnapshot.val();

        const numReferredUsers = referredUsers ? Object.keys(referredUsers).length : 0;

        res.status(200).json({ referralCode: referralCode, numReferredUsers: numReferredUsers });

    } catch (error) {
        console.error('Error fetching referrals:', error);
        res.status(500).json({ message: 'Failed to retrieve referrals.', error: error.message });
    }
});

// --------------------------------------------------------------------
//  Utility Functions (same as before + new functions)
// --------------------------------------------------------------------

function generateReferralCode() {
    return Math.random().toString(36).substring(2, 10).toUpperCase();
}

function calculateHMACSignature(params, apiKey) {
    // 1. Get all request parameters
    const paramKeys = Object.keys(params);

    // 2. Order the request parameters alphabetically
    paramKeys.sort();

    // 3. Build the ordered request parameter string
    let sigString = '';
    for (const key of paramKeys) {
        sigString += `${key}=${params[key]}`;
    }

    // Create the HMAC hash using SHA256
    const hmac = crypto.createHmac('sha256', apiKey);
    hmac.update(sigString);
    return hmac.digest('hex');
}

function generateSpinReward() {
    // Replace with your actual spin logic.  This is a placeholder.
    const rewards = [
        { message: 'You won 100 coins!', coins: 100 },
        { message: 'You won 50 coins!', coins: 50 },
        { message: 'Better luck next time!', coins: 0 },
        { message: 'You won 200 coins!', coins: 200 }
    ];

    const randomIndex = Math.floor(Math.random() * rewards.length);
    return rewards[randomIndex];
}


// Start the server (same as before)
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});