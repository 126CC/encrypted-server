const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors({
    methods: ['GET', 'POST', 'PUT', 'DELETE'] // Specify allowed methods
}));
app.use(bodyParser.json());
const port = 3000;

app.listen(port, () => {
    console.log(`Server started on port ${port}`);
})

const crypto = require('crypto');
const req = require("express/lib/request");

const generateKeys = () => {
    const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // Recommended key size for security
        publicKeyEncoding: {
            type: 'spki', // Recommended for public keys
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs8', // Recommended for private keys
            format: 'pem',
        },
    });
    console.log('Private Key:', keys.privateKey);
    console.log('Public Key:', keys.publicKey);
    return keys;
}

let {publicKey, privateKey} = generateKeys();

const decryptData = (base64Data) => {
    // 1. Convert from encoded string to a buffer
    const buffer = Buffer.from(base64Data, 'base64');

    // 2. Explicitly define padding and hash to match the Web Crypto API
    return crypto.privateDecrypt(
        {
            key: privateKey, // Your 2048-bit key from generateKeys()
            oaepHash: "sha256", // MUST BE THIS to match client's "SHA-256"
        },
        buffer
    ).toString("utf8");
};

function createUser(user, password) {
    const salt = crypto.randomBytes(16).toString('hex');

    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
        if (err) throw err;

        const hash = derivedKey.toString('hex');

        const newUser = {
            username: user,
            salt: salt,
            hash: hash,
            data: " "
        };

        users.push(newUser);

    })

}

function verifyPassword(inputPassword, storedSalt, storedHash, actionOnSuccess, actionOnFail) {
    crypto.scrypt(inputPassword, storedSalt, 64, (err, derivedKey) => {
        if (err) throw err;

        const inputHash = derivedKey.toString('hex');

        // Compare the newly generated hash with the one stored in the database
        if(storedHash === inputHash) {
            actionOnSuccess();
        } else
            actionOnFail();
    });
}

let users = [];

let admins = [
    {
        username: 'Mr. Goldstein',
        hash: 'ff5de730fa61e4b9d3ec2298efdce03e24240fb00d45f0d21f4644cda8c85ac4864091d93eefbfbb3b44b11fd6a8107d7f4675f9d4c93fc2503c27b9aa927dc8',
        salt: '19bc8c2e05f668a19bccc5262042af2b'
    },
    {
        username: 'charchar',
        hash: 'ff5de730fa61e4b9d3ec2298efdce03e24240fb00d45f0d21f4644cda8c85ac4864091d93eefbfbb3b44b11fd6a8107d7f4675f9d4c93fc2503c27b9aa927dc8',
        salt: '19bc8c2e05f668a19bccc5262042af2b'
    }
];

const urlSafeToBase64 = (urlSafeStr) => {
    // Add padding back for standard Base64 if needed
    let standardB64 = urlSafeStr.replace(/-/g, '+').replace(/_/g, '/');
    while (standardB64.length % 4) {
        standardB64 += '=';
    }
    return standardB64;
};

app.get('/public_key', (req, res) => {
    res.json(publicKey)
})

app.post('/user', (req, res) => {
    console.log(req.body);
    const {encryptedUserName, encryptedPassword} = req.body;
    let decryptUserName = decryptData(encryptedUserName);
    let decryptedPassword = decryptData(encryptedPassword);

    for(let i = 0; i < users.length; i++) {
        if(users[i].username === decryptUserName) {
            return res.status(400).json({error: "Please type in a valid user and pass"});
        }
    }

    for(let i = 0; i < admins.length; i++) {
        if(admins[i].username === decryptUserName) {
            return res.status(400).json({error: "Please type in a valid user and pass"});
        }
    }

    createUser(decryptUserName, decryptedPassword);
    console.log('User created', JSON.stringify(decryptUserName, null, 2));
    return res.status(201).json("User created successfully.");
})

app.put('/data', (req, res) => {
    console.log(req.body);
    const {encryptedUserName, encryptedPassword, encryptedData} = req.body;
    const {user} = req.query;

    let decryptedUserName = decryptData(encryptedUserName);
    let decryptedPassword = decryptData(encryptedPassword);
    let decryptedData = decryptData(encryptedData);

    let adminCheck = false;
    let adminIndex = -1;
    let userCheck = false;
    let userIndex = -1;


    if(!encryptedUserName || !encryptedPassword) {
        res.status(400).json({error: "Please type in a valid user and pass"});
    }

    for(let i = 0; i < admins.length; i++) {
        if(admins[i].username === decryptedUserName) {
            adminCheck = true;
            adminIndex = i;
        }
    }

    if(adminCheck) {
        for(let i = 0; i < users.length; i++) {
            if(users[i].username === user) {
                userCheck = true;
                userIndex = i;
            }
        }
    } else {
        for(let i = 0; i < users.length; i++) {
            if(users[i].username === decryptedUserName) {
                userCheck = true;
                userIndex = i;
            }
        }
    }

    if(userCheck) {
        if(adminCheck) {
            for(let i = 0; i < users.length; i++) {
                    verifyPassword(decryptedPassword, admins[adminIndex].salt, admins[adminIndex].hash, () => {
                        if(users[i].username === user) {
                            users[userIndex].data = decryptedData;
                            res.status(200).json("Data updated");
                            console.log(users[userIndex].data);
                        }
                    }, () => {
                        res.status(403).json("Password invalid");
                        console.log("Password invalid for admin");
                    });
            }
        } else {
            for(let i = 0; i < users.length; i++) {
                    verifyPassword(decryptedPassword, users[userIndex].salt, users[userIndex].hash, () => {
                        if(users[i].username === decryptedUserName) {
                            users[userIndex].data = decryptedData;
                            res.status(200).json("Data updated");
                            console.log(users[userIndex].data);
                        }
                    }, () => {
                        res.status(403).json("Password invalid");
                        console.log("Password invalid for user");
                    })
            }
        }
    } else {
        console.log("User does not exist");
        res.status(401).json({error: 'user does not exist'});
    }


})

app.get('/data', (req, res) => {
    const {u, p} = req.query;
    const {user} = req.query;
    const encryptedUsername = urlSafeToBase64(u);
    const encryptedPassword = urlSafeToBase64(p);
    const decryptedUsername = decryptData(encryptedUsername);
    const decryptedPassword = decryptData(encryptedPassword);

    let adminCheck = false;
    let adminIndex = -1;
    let userCheck = false;
    let userIndex = -1;

    for(let i = 0; i < admins.length; i++) {
        if(decryptedUsername === admins[i].username) {
            adminCheck = true;
            adminIndex = i;
        }
    }

    if(adminCheck) {
        for(let i = 0; i < users.length; i++) {
            if(user === users[i].username) {
                userCheck = true;
                userIndex = i;
            }
        }
    } else {
        for(let i = 0; i < users.length; i++) {
            if(decryptedUsername === users[i].username) {
                userCheck = true;
                userIndex = i;
            }
        }
    }

    if(userCheck) {
        if(adminCheck) {
            verifyPassword(decryptedPassword, admins[adminIndex].salt, admins[adminIndex].hash, () => {
                res.status(200).json("Data: " + users[userIndex].data);
                console.log(users[userIndex].data + "Data given to admin");
            }, () => {
                res.status(403).json("Password invalid");
                console.log("Password invalid for admin");
            })
        } else {
            verifyPassword(decryptedPassword, users[userIndex].salt, users[userIndex].hash, () => {
                res.status(200).json("Data: " + users[userIndex].data);
                console.log("Data given to user");
            }, () => {
                res.status(403).json("Password invalid");
                console.log("Password invalid for user");
            })
        }
    } else {
        console.log("User does not exist" + userCheck + adminCheck);
        res.status(401).json({error: 'user does not exist'});
    }
})