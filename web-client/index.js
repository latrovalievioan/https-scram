import {generateClientKey, generateSalt, generateSaltedPassword, generateServerKey, generateStoredKey} from '../crypto/index.js'

const ITERATIONS_COUNT = 100_000

const registerButton = document.getElementById("register-btn")

const register = async() => {
    const registerEmail = document.getElementById("reg-email").value
    const registerPassword = document.getElementById("reg-password").value

    const salt = generateSalt()
    const saltedPassword = await generateSaltedPassword(registerPassword, salt, ITERATIONS_COUNT)
    const clientKey = await generateClientKey(saltedPassword)
    const serverKey = await generateServerKey(saltedPassword)
    const storedKey = await generateStoredKey(clientKey)

    const registerParams = {
        registerEmail,
        serverKey: btoa(String.fromCharCode(...serverKey)),
        storedKey: btoa(String.fromCharCode(...storedKey)),
        salt
    }

    console.log(registerParams)

    //TODO: fetch post with registerParams
}

registerButton.onclick = register
