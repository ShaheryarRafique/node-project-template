const { check, body, validationResult } = require('express-validator');

const dns = require('dns');

const emailDomainIsValid = (email) => {
  return new Promise((resolve, reject) => {
    const domain = email.split('@')[1];
    dns.resolveMx(domain, (err, addresses) => {
      if (err) reject(err);
      resolve(addresses && addresses.length > 0);
    });
  });
};

// Auth Validations
const authValidations = {
    register: [
        check('email')
            .isEmail().withMessage('Please provide a valid email address.')
            .bail()
            .custom(async (email) => {
                const isValidDomain = await emailDomainIsValid(email);
                if (!isValidDomain) {
                    throw new Error('Email domain has no MX records, thus cannot receive emails.');
                }
                return true;
            }),
        check('password')
            .isLength({ min: 8 })
            .withMessage('Password must be at least 8 characters long.'),
        check('name')
            .not().isEmpty()
            .withMessage('Name is required.'),
        body('confirmPassword')
            .custom((value, { req }) => {
                if (value !== req.body.password) {
                    throw new Error('Passwords do not match');
                }
                return true;
            }),
    ],
    login: [
        check('email').isEmail().withMessage('Please provide a valid email address.'),
        check('password').not().isEmpty().withMessage('Password is required.'),
    ],
    forgotPassword: [
        check('email').isEmail().withMessage('Please provide a valid email address.'),
    ],
    resetPassword: [
        check('password')
            .isLength({ min: 8 })
            .withMessage('Password must be at least 8 characters long.'),
        check('confirmPassword')
            .custom((value, { req }) => {
                if (value !== req.body.password) {
                    throw new Error('Passwords do not match');
                }
                return true;
            }),
    ],
};
// Add other validations if needed
const userValidations = {
    updateProfile: [
        check('name').not().isEmpty().withMessage('Name is required.'),
        // Other checks for profile update can be added here
    ],
};

module.exports = {
    authValidations,
    userValidations,
};
