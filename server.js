// --- Imports ---
import express from 'express';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import multer from 'multer';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import GoogleStrategy from 'passport-google-oauth20';
import session from 'express-session';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import 'dotenv/config';

// --- ADD THESE TWO LINES FOR DEBUGGING ---
console.log('GOOGLE_CLIENT_ID from .env:', process.env.GOOGLE_CLIENT_ID);
console.log('Is .env file being read? If the line above is "undefined", the answer is NO.');
// -----------------------------------------

// --- Configuration ---
const PORT = process.env.PORT || 5000;
const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

// --- Database Connection ---
const { Pool } = pg;
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});
pool.connect().then(() => console.log('Successfully connected to the database.'));

// --- Middleware ---
app.use(cors());
app.use(express.json());
app.use(session({
    secret: 'a_separate_secret_for_session',
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());

// --- Passport & Google OAuth2 Strategy ---
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, result.rows[0]);
    } catch (error) {
        done(error, null);
    }
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const email = profile.emails[0].value;
        const fullName = profile.displayName;

        let userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        let user = userResult.rows[0];

        if (!user) {
            // If user doesn't exist, create a new one. Note: password_hash is null for OAuth users.
            const newUserResult = await pool.query(
                'INSERT INTO users (full_name, email, password_hash) VALUES ($1, $2, $3) RETURNING *',
                [fullName, email, null]
            );
            user = newUserResult.rows[0];
        }

        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
}));


// --- Multer Setup ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const uploadDir = join(__dirname, 'uploads');
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({ storage, limits: { fileSize: 1024 * 1024 * 5 } });
app.use('/uploads', express.static(uploadDir));


// --- JWT Verification ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(403).json({ message: 'Authorization required.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Invalid or expired token.' });
    }
};

// --- API Routes ---

// 1. User Registration Route
app.post('/api/register', async (req, res) => {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) {
            return res.status(409).json({ message: 'An account with this email already exists.' });
        }

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser = await pool.query(
            'INSERT INTO users (full_name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, full_name, created_at',
            [fullName, email, passwordHash]
        );
        
        const user = newUser.rows[0];
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({
            message: 'User registered successfully!',
            user: { id: user.id, email: user.email, fullName: user.full_name, memberSince: user.created_at },
            token: token,
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// 2. User Login Route
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({
            message: 'Login successful!',
            user: {
                id: user.id,
                email: user.email,
                fullName: user.full_name,
                memberSince: user.created_at,
            },
            token: token,
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});


// --- Google Authentication Routes ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login.html' }), (req, res) => {
    // On successful authentication, create a JWT for the user
    const token = jwt.sign({ userId: req.user.id }, JWT_SECRET, { expiresIn: '1h' });
    const userName = req.user.full_name;
    
    // Redirect to the login page, which will save the token and redirect to the dashboard
    res.redirect(`/login.html?token=${token}&userName=${encodeURIComponent(userName)}`);
});

// 4. GET Listings Route (Public)
app.get('/api/listings', async (req, res) => {
    try {
        const { borough, minPrice, maxPrice, sortBy } = req.query;

        let query = 'SELECT id, borough, area_sqm, image_url, description, pdf_path, room_data_json, created_at FROM listings';
        const queryParams = [];
        const conditions = [];

        if (borough) {
            queryParams.push(`%${borough}%`);
            conditions.push(`borough ILIKE $${queryParams.length}`);
        }

        if (minPrice && !isNaN(parseInt(minPrice))) {
            const minP = parseInt(minPrice);
            if (minP > 0) {
                queryParams.push(minP);
                conditions.push(`EXISTS (SELECT 1 FROM jsonb_array_elements(room_data_json) AS room WHERE (room->>'price')::int >= $${queryParams.length})`);
            }
        }

        if (maxPrice && !isNaN(parseInt(maxPrice))) {
            const maxP = parseInt(maxPrice);
            if (maxP > 0) {
                queryParams.push(maxP);
                conditions.push(`EXISTS (SELECT 1 FROM jsonb_array_elements(room_data_json) AS room WHERE (room->>'price')::int <= $${queryParams.length})`);
            }
        }
        
        if (conditions.length > 0) {
            query += ' WHERE ' + conditions.join(' AND ');
        }
        
        let orderByClause = 'ORDER BY created_at DESC';
        if (sortBy) {
            switch (sortBy) {
                case 'price_asc':
                    orderByClause = 'ORDER BY area_sqm ASC'; 
                    break;
                case 'price_desc':
                    orderByClause = 'ORDER BY area_sqm DESC'; 
                    break;
                case 'area_desc':
                    orderByClause = 'ORDER BY area_sqm DESC';
                    break;
                case 'area_asc':
                    orderByClause = 'ORDER BY area_sqm ASC';
                    break;
                case 'date_desc':
                default:
                    orderByClause = 'ORDER BY created_at DESC';
                    break;
            }
        }
        
        query += ' ' + orderByClause;

        const result = await pool.query(query, queryParams);
        res.status(200).json(result.rows);

    } catch (error) {
        console.error('Error fetching listings:', error);
        res.status(500).json({ message: 'Failed to fetch listings due to a server error.' });
    }
});

// 5. GET Landlord Listings Route (Protected)
app.get('/api/landlord/listings', verifyToken, async (req, res) => {
    try {
        const ownerId = req.userId;
        const result = await pool.query(
            'SELECT id, borough, area_sqm, image_url, description, pdf_path, room_data_json FROM listings WHERE owner_id = $1 ORDER BY created_at DESC',
            [ownerId]
        );
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Error fetching landlord listings:', error);
        res.status(500).json({ message: 'Failed to fetch your listings due to a server error.' });
    }
});

// 6. GET User Profile Route (Protected)
app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const ownerId = req.userId;
        const result = await pool.query(
            'SELECT full_name, email, created_at FROM users WHERE id = $1',
            [ownerId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const user = result.rows[0];

        res.status(200).json({
            fullName: user.full_name,
            email: user.email,
            memberSince: user.created_at,
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ message: 'Failed to fetch user profile due to a server error.' });
    }
});


// 7. POST Listing Route (Protected - Requires JWT & Multer)
app.post('/api/listings', verifyToken, upload.single('propertyExpose'), async (req, res) => {
    try {
        const ownerId = req.userId;
        const { borough, area_sqm, mainImageUrl, description, roomData } = req.body;
        const pdfPath = req.file ? `/uploads/${req.file.filename}` : null;
        
        if (!borough || !area_sqm || !mainImageUrl || !description || !pdfPath || !roomData) {
            return res.status(400).json({ message: 'All required fields, PDF exposé, and room data must be provided.' });
        }

        const newListing = await pool.query(
            'INSERT INTO listings (owner_id, borough, area_sqm, image_url, description, pdf_path, room_data_json) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
            [ownerId, borough, area_sqm, mainImageUrl, description, pdfPath, roomData]
        );

        res.status(201).json({
            message: 'Listing submitted successfully and is awaiting review!',
            listingId: newListing.rows[0].id,
        });

    } catch (error) {
        if (error.message === 'Only PDF files are allowed for property exposés.') {
             return res.status(400).json({ message: error.message });
        }
        console.error('Listing submission error:', error);
        res.status(500).json({ message: 'Failed to submit listing due to a server error.' });
    }
});

// 8. PUT/PATCH Listing Route (Protected)
app.put('/api/listings/:id', verifyToken, async (req, res) => {
    try {
        const listingId = req.params.id;
        const ownerId = req.userId;
        const { borough, area_sqm, mainImageUrl, description } = req.body;

        if (!borough || !area_sqm || !mainImageUrl || !description) {
            return res.status(400).json({ message: 'All required fields must be provided.' });
        }

        const result = await pool.query(
            'UPDATE listings SET borough = $1, area_sqm = $2, image_url = $3, description = $4 WHERE id = $5 AND owner_id = $6 RETURNING id',
            [borough, area_sqm, mainImageUrl, description, listingId, ownerId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'Listing not found or you do not own this listing.' });
        }

        res.status(200).json({
            message: `Listing ${listingId} updated successfully.`,
            listingId: listingId,
        });

    } catch (error) {
        console.error('Listing update error:', error);
        res.status(500).json({ message: 'Failed to update listing due to a server error.' });
    }
});

// 9. DELETE Listing Route (Protected)
app.delete('/api/listings/:id', verifyToken, async (req, res) => {
    try {
        const listingId = req.params.id;
        const ownerId = req.userId;

        const result = await pool.query(
            'DELETE FROM listings WHERE id = $1 AND owner_id = $2',
            [listingId, ownerId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'Listing not found or you do not own this listing.' });
        }

        res.status(200).json({ message: `Listing ${listingId} deleted successfully.` });

    } catch (error) {
        console.error('Listing deletion error:', error);
        res.status(500).json({ message: 'Failed to delete listing due to a server error.' });
    }
});

// 10. Serve Static HTML Files
app.use(express.static(__dirname)); 
app.use(express.static(join(__dirname, '..')));

// --- Server Start ---
app.listen(PORT, () => {
    console.log(`Server is listening on http://localhost:${PORT}`);
});