
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
        console.log(hash);
        console.log(salt);

    })

}

createUser('charlotte', 'charchar');
createUser('rachel', 'rachrach');
createUser('anya', 'anyany');
createUser('aidan', 'aidaid');
createUser('matthew', 'mattmatt');