const express = require('express');
const Employee = require('../models/EmployeeModel.js');
const router = express.Router();

// Get all employees
router.get('/employees', async (req, res) => {
    try {
        const employees = await Employee.find();
        res.status(200).json(employees);
    } catch (err) {
        res.status(500).send({ message: "Error retrieving employees" });
    }
});

// Create a new employee
router.post('/employees', async (req, res) => {
    try {
        const newEmployee = new Employee({
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            email: req.body.email,
            position: req.body.position,
            salary: req.body.salary,
            date_of_joining: req.body.date_of_joining,
            department: req.body.department,
        });

        const savedEmployee = await newEmployee.save();
        res.status(201).json(savedEmployee);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

module.exports = router;

// Get employee details by employee ID
router.get('/employees/:eid', async (req, res) => {
    try {
        const employee = await Employee.findById(req.params.eid);
        if (!employee) {
            return res.status(404).send({ message: "Employee not found." });
        }
        res.status(200).json(employee);
    } catch (err) {
        res.status(500).send({ message: "Error retrieving employee." });
    }
});

// Update employee details
router.put('/employees/:eid', async (req, res) => {
    try {
        const updatedEmployee = await Employee.findByIdAndUpdate(req.params.eid, req.body, { new: true });
        if (!updatedEmployee) {
            return res.status(404).send({ message: "Employee not found." });
        }
        res.status(200).send({ message: "Employee details updated successfully." });
    } catch (err) {
        res.status(500).send({ message: "Error updating employee." });
    }
});

// Delete employee by employee ID
router.delete('/employees/:eid', async (req, res) => {
    const { eid } = req.params;
    
    try {
        const result = await Employee.findByIdAndDelete(eid);
        if (!result) {
            return res.status(404).send({ message: "Employee not found." });
        }
        res.status(200).send({ message: "Employee deleted successfully." }); 
    } catch (err) {
        res.status(500).send({ message: "Error deleting employee." });
    }
});

module.exports = router;
