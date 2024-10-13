const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const userRoutes = require('./routes/UserRoutes.js');
const employeeRoutes = require('./routes/EmployeeRoutes.js');

const DB_URL = "mongodb+srv://liuch:1vK0vApEseaWLrMl@cluster0.egrgn.mongodb.net/COMP3123-assignment?retryWrites=true&w=majority&appName=Cluster0";
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use('/api/v1/user', userRoutes);
app.use('/api/v1/emp', employeeRoutes);

mongoose.Promise = global.Promise;

mongoose.connect(DB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("Successfully connected to the MongoDB Atlas server");
}).catch(err => {
    console.log('Could not connect to the database. Exiting now...', err);
    process.exit();
});

app.get('/', (req, res) => {
    res.send("<h1>Welcome to the Employee Management System</h1>");
});

app.listen(5050, () => {
    console.log("Server is listening on port 5050");
});