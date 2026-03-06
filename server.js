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
        console.log(newUser);

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
        username: "33",
        hash: '82ec67c8ba77a83b9499fb8ba5fb3d7f1eda2bfefb51bc1ddd0dddb323cf944f0ecfe0f1a31c89b90fe702aff0a2d6551c5d5a63b6835b5bb8076c9bfd81f7b0',
        salt: 'c6535e5c63692dd5815513177ce74043'
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

    let adminIndex = -1;
    let targetIndex = -1;
    let targetUser;


    if(!encryptedUserName || !encryptedPassword || !encryptedData) {
        res.status(400).json({error: "Invalid input"});
    }

    for(let i = 0; i < admins.length; i++) {
        if(admins[i].username === decryptedUserName) {
            adminIndex = i;
            console.log("Admin auth attempt", decryptedUserName);
        }
    }

    if(adminIndex === -1) {
        targetUser = user;
        console.log("Admin target user", targetUser);
    } else {
        targetUser = decryptedUserName;
        console.log("User targets self", targetUser);
    }

    for(let i = 0; i < users.length; i++) {
        if(users[i].username === targetUser) {
            targetIndex = i;
        }
    }

    if(targetIndex === -1) {
        console.log("Put failed - User not found", targetUser);
        return res.status(404).json({error: "User does not exist"});
    }

    let account;
    if (adminIndex !== -1) {
        account = admins[adminIndex];
    } else {
        account = users[targetIndex];
    }

    verifyPassword(
        decryptedPassword,
        account.salt,
        account.hash,
        () => {
            users[targetIndex].data = decryptedData;
            console.log("DATA UPDATED FOR:", targetUser);
            res.status(200).json("Data updated");
        },
        () => {
            console.log("PASSWORD INVALID FOR:", decryptedUserName);
            res.status(403).json("Password is invalid");
        }
    );
});

app.get('/data', (req, res) => {
    const {u, p, user} = req.query;
    const encryptedUsername = urlSafeToBase64(u);
    const encryptedPassword = urlSafeToBase64(p);
    const decryptedUsername = decryptData(encryptedUsername);
    const decryptedPassword = decryptData(encryptedPassword);

    let adminIndex = -1;
    let targetIndex = -1;
    let targetUser;


    if(!u || !p || !user) {
        return res.status(400).json({error: "Invalid input"});
    }

    for(let i = 0; i < admins.length; i++) {
        if(admins[i].username === decryptedUsername) {
            adminIndex = i;
            console.log("Admin read attempt", decryptedUsername);
        }
    }

    if (adminIndex !== -1) {
        targetUser = user;
    } else {
        targetUser = decryptedUsername;
    }

    for (let i = 0; i < users.length; i++) {
        if (users[i].username === targetUser) {
            targetIndex = i;
        }
    }

    if (targetIndex === -1) {
        console.log("GET FAILED — USER NOT FOUND:", targetUser);
        return res.status(404).json({ error: 'user does not exist' });
    }

    let account;
    if (adminIndex !== -1) {
        account = admins[adminIndex];
    } else {
        account = users[targetIndex];
    }

    verifyPassword(
        decryptedPassword,
        account.salt,
        account.hash,
        () => {
            console.log("DATA READ FOR:", targetUser);
            res.status(200).json("data: " + users[targetIndex].data);
        },
        () => {
            console.log("PASSWORD INVALID FOR:", decryptedUsername);
            res.status(403).json("password is invalid");
        }
    );
});