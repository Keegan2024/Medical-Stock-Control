const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect('mongodb://localhost/nacs', { useNewUrlParser: true, useUnifiedTopology: true });

// User Schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    facility: String,
    role: { type: String, default: 'facility' },
    status: { type: String, default: 'pending' }
});

// Facility Schema
const facilitySchema = new mongoose.Schema({
    name: String,
    province: String,
    district: String,
    hub: String
});

// Commodity Schema
const commoditySchema = new mongoose.Schema({
    name: String,
    type: String
});

// Report Schema
const reportSchema = new mongoose.Schema({
    week: String,
    month: String,
    year: String,
    facility: String,
    commodities: [{
        name: String,
        expiryDate: String,
        openingBalance: Number,
        received: Number,
        used: Number,
        givenToFacility: String,
        closingBalance: Number
    }],
    nacs: {
        totalScreened: Number,
        eligibleForHEPS: Number,
        hepsGiven: Number,
        totalRefill: Number,
        hepsGivenToOtherDept: Number,
        hepsStockOnHand: Number
    },
    other: {
        clientsSeen: Number,
        dueForDrugDelivery: Number,
        given6MMD: Number,
        given3to5MMD: Number,
        givenLessThan3MMD: Number,
        totalClientsDueForVL: Number,
        totalVLSamplesCollected: Number,
        totalTPTInitiations: Number,
        pDTGCurr: Number,
        transitionedToPALD: Number,
        totalOnPALD: Number,
        soh: Number,
        threeHPWeeklyInitiations: Number,
        fyOn3HPCummulative: Number
    },
    status: { type: String, default: 'pending' },
    createdBy: String
});

const User = mongoose.model('User', userSchema);
const Facility = mongoose.model('Facility', facilitySchema);
const Commodity = mongoose.model('Commodity', commoditySchema);
const Report = mongoose.model('Report', reportSchema);

// Middleware for authentication
const authMiddleware = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    
    try {
        const decoded = jwt.verify(token, 'secret');
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Auth Routes
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || user.status !== 'approved') return res.status(401).json({ message: 'Invalid credentials or pending approval' });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user._id, role: user.role }, 'secret', { expiresIn: '1h' });
    res.json({ token, user: { id: user._id, username: user.username, role: user.role, facility: user.facility } });
});

app.post('/api/auth/signup', async (req, res) => {
    const { username, password, facility, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword, facility, role });
    await user.save();
    res.json({ message: 'User created, pending approval' });
});

app.get('/api/auth/verify', authMiddleware, async (req, res) => {
    const user = await User.findById(req.user.id);
    res.json({ user: { id: user._id, username: user.username, role: user.role, facility: user.facility } });
});

// Facility Routes
app.get('/api/facilities', authMiddleware, async (req, res) => {
    const facilities = await Facility.find();
    res.json(facilities);
});

app.post('/api/facilities', authMiddleware, async (req, res) => {
    if (req.user.role === 'facility') return res.status(403).json({ message: 'Unauthorized' });
    const facility = new Facility(req.body);
    await facility.save();
    res.json(facility);
});

// Commodity Routes
app.get('/api/commodities', authMiddleware, async (req, res) => {
    const commodities = await Commodity.find();
    res.json(commodities);
});

app.post('/api/commodities', authMiddleware, async (req, res) => {
    if (req.user.role === 'facility') return res.status(403).json({ message: 'Unauthorized' });
    const commodity = new Commodity(req.body);
    await commodity.save();
    res.json(commodity);
});

// Report Routes
app.get('/api/reports', authMiddleware, async (req, res) => {
    const reports = req.user.role === 'facility' 
        ? await Report.find({ createdBy: req.user.id })
        : await Report.find();
    res.json(reports);
});

app.get('/api/reports/status', authMiddleware, async (req, res) => {
    const reports = req.user.role === 'facility' 
        ? await Report.find({ createdBy: req.user.id })
        : await Report.find();
    res.json(reports);
});

app.post('/api/reports', authMiddleware, async (req, res) => {
    const report = new Report({ ...req.body, createdBy: req.user.id });
    await report.save();
    res.json(report);
});

app.post('/api/reports/:id/approve', authMiddleware, async (req, res) => {
    if (req.user.role === 'facility') return res.status(403).json({ message: 'Unauthorized' });
    const report = await Report.findByIdAndUpdate(req.params.id, { status: 'Approved' }, { new: true });
    res.json(report);
});

app.post('/api/reports/:id/reject', authMiddleware, async (req, res) => {
    if (req.user.role === 'facility') return res.status(403).json({ message: 'Unauthorized' });
    const report = await Report.findByIdAndUpdate(req.params.id, { status: 'Rejected' }, { new: true });
    res.json(report);
});

// User Management Routes
app.get('/api/users', authMiddleware, async (req, res) => {
    if (req.user.role === 'facility') return res.status(403).json({ message: 'Unauthorized' });
    const users = await User.find();
    res.json(users);
});

app.post('/api/users/:id/approve', authMiddleware, async (req, res) => {
    if (req.user.role === 'facility') return res.status(403).json({ message: 'Unauthorized' });
    await User.findByIdAndUpdate(req.params.id, { status: 'approved' });
    res.json({ message: 'User approved' });
});

app.post('/api/users/:id/reject', authMiddleware, async (req, res) => {
    if (req.user.role === 'facility') return res.status(403).json({ message: 'Unauthorized' });
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User rejected' });
});

app.listen(3000, () => console.log('Server running on port 3000'));
