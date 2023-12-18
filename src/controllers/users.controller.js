const bcrypt = require('bcryptjs');
const userDao = require('../dao/user.dao');
const { userModel } = require('../models/user.model');
const errorHandlers = require('../services/errors/errorHandler');
const { getUserRoleFromDatabase } = require('../utils/function');

//Renderizar la página de registro
function renderRegisterPage(req, res) {
    res.render('register');
}

//Agregar un nuevo usuario
async function registerUser(req, res) {
    try {
        const { nombre, apellido, edad, email, pass } = req.body;

        const usuarioCreado = await userDao.createUser({
            nombre,
            apellido,
            edad,
            email,
            pass,
        });

        if (!usuarioCreado) {
            errorHandlers.customErrorHandler('usuarioExistente', res); //Manejo de error personalizado
        } else {
            req.logger.info('Usuario registrado con éxito:', email);
            res.redirect('login');
        }
    } catch (error) {
        req.logger.error('Error en el servidor:', error);
        // errorHandlers.customErrorHandler('errorServidor', res); //Manejo de error personalizado
    }
}

//Renderizar la página de inicio de sesión
function renderLoginPage(req, res) {
    res.render('login');
}

//Iniciar sesión del usuario
async function loginUser(req, res) {
    try {
        const { email, pass } = req.body;
        const usuario = await userDao.findUserByEmail(email);

        if (!usuario) {
            errorHandlers.customErrorHandler('usuarioNoEncontrado', res);
        } else {
            const isPasswordValid = await bcrypt.compare(pass, usuario.pass);

            if (!isPasswordValid) {
                errorHandlers.customErrorHandler('contrasenaIncorrecta', res);
            } else {
                // Actualiza la propiedad last_connection al momento del login
                usuario.last_connection = new Date();
                await usuario.save();

                req.session.userId = usuario._id;
                req.session.email = email;
                res.redirect('/');
            }
        }
    } catch (error) {
        req.logger.error('Error en el servidor:', error);
    }
}

//Cerrar la sesión del usuario
async function logoutUser(req, res) {
    try {
        const userId = req.session.userId;

        // Encuentra al usuario y actualiza la propiedad last_connection al momento del logout
        const user = await userModel.findById(userId);
        if (user) {
            user.last_connection = new Date();
            await user.save();
        }

        req.session.destroy((err) => {
            if (err) {
                req.logger.error('Error al cerrar sesión:', err);
                return res.status(500).json({ mensaje: 'Error al cerrar sesión' });
            }
            res.redirect('/login');
        });
    } catch (error) {
        req.logger.error('Error en el servidor:', error);
        res.status(500).json({ mensaje: 'Error al cerrar sesión' });
    }
}

//Renderiza la vista del perfil del usuario
async function renderProfile(req, res) {
    const userId = req.session.userId;
    const usuario = await userModel.findById(userId);
    const userRole = await getUserRoleFromDatabase(userId);

    let isPremium = false;
    let isAdmin = false;

    if (userRole === 'premium') {
        isPremium = true;
    }else if (userRole === 'admin'){
        isAdmin = true;
    }

    res.render('perfil', {
        userId: usuario.id,
        nombreUsuario: usuario.nombre,
        userEmail: usuario.email,
        userRol: usuario.rol,
        isPremium,
        isAdmin,
    })
}

//Funcion para verificar el rol del usuario
async function checkUserRole(req, res) {
    try {
        const userId = req.session.userId; 

        const user = await userModel.findById(userId);

        if (user && (user.rol === 'premium' || user.rol === 'admin')) {
            res.status(200).send();
        } else {
            res.status(403).json({ mensaje: 'Acceso no autorizado' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ mensaje: 'Error en el servidor' });
    }
}

//Cambiar el rol del usuario a premium o user
async function changeUserRole(req, res) {
    try {
        const userIdToUpdate = req.body.userIdToUpdate;
        const newRole = req.body.newRole;

        //Verifica si el usuario actual tiene permisos para cambiar roles
        await checkUserRole(req, res);

        //Verifica si el nuevo rol es válido (user o premium)
        if (newRole !== 'user' && newRole !== 'premium') {
            return res.status(400).json({ message: 'Rol no válido. Use "user" o "premium".' });
        }

        const updatedUser = await userModel.findByIdAndUpdate(
            userIdToUpdate,
            { rol: newRole },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        res.status(200).json({ message: `Rol del usuario ${userIdToUpdate} actualizado a ${newRole}` });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
}

async function renderAllUsers(req, res) {
    res.render('change-rol');
}

module.exports = {
    renderRegisterPage,
    registerUser,
    renderLoginPage,
    loginUser,
    logoutUser,
    renderProfile,
    checkUserRole,
    changeUserRole,
    renderAllUsers,
};
