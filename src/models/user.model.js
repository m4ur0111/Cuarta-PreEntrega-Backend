const mongoose = require('mongoose');

const userCollection = "users"

const userSchema = new mongoose.Schema({
    nombre: { type: String, required: true, max: 100 },
    apellido: { type: String, max: 100 },
    edad: { type: Number, required: true },
    email: { type: String, required: true, max: 100 },
    pass: { type: String, max: 50 },
    rol: { type: String, default: 'user' }, // Rol por defecto: 'user'
    documents: [
        {
            name: { type: String, required: true },
            reference: { type: String, required: true }
        }
    ],
    last_connection: { type: Date } // Nueva propiedad last_connection
});

// Agregar el método personalizado findById
userSchema.statics.findById = function(id, callback) {
    return this.findOne({ _id: id }, callback);
};

userSchema.methods.isPremium = function () {
    return this.rol.includes('premium');
};

const userModel = mongoose.model(userCollection, userSchema);

module.exports = { userModel };
