// Load required packages
const mongoose = require('mongoose')

// Define our client schema
const ClientSchema = new mongoose.Schema({
    name: { type: String, unique: true, required: true },
    id: { type: String, required: true},
    secret: { type: String, required: true },
    userId: { type: String, required: true }
})

// Export the Mongoose model
module.exports = mongoose.model('Client', ClientSchema)
