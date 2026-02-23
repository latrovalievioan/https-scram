import {
    generateAuthMessage,
    generateClientKey,
    generateNonce,
    generateSalt,
    generateSaltedPassword,
    generateServerKey,
    generateSignature,
    generateStoredKey,
    xorUint8Arrays,
} from "../crypto/index.js";

const ITERATIONS_COUNT = 100_000;

const SERVER_URL = "http://localhost:3000";

const register = async () => {
    const registerEmail = document.getElementById("reg-email").value;
    const registerPassword = document.getElementById("reg-password").value;

    const salt = generateSalt();
    const saltedPassword = await generateSaltedPassword(
        registerPassword,
        salt,
        ITERATIONS_COUNT
    );
    const clientKey = await generateClientKey(saltedPassword);
    const serverKey = await generateServerKey(saltedPassword);
    const storedKey = await generateStoredKey(clientKey);

    const registerParams = {
        registerEmail,
        base64ServerKey: btoa(String.fromCharCode(...serverKey)),
        base64StoredKey: btoa(String.fromCharCode(...storedKey)),
        salt,
        iterations: ITERATIONS_COUNT,
    };

    const resp = await fetch(`${SERVER_URL}/register`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(registerParams),
    });

    if (!resp.ok) {
        alert("Registration failed");
        return;
    }

    alert("Registration completed successfully");
};

document.getElementById("register-btn").onclick = register;

/**
 * @typedef {Object} ServerFistMessage
 * @property {number} iterations
 * @property {string} fullNonce
 * @property {string} salt
 *
 * @typedef {Object} ServerFinalMessage
 * @property {string} base64ServerSignature
 */
const authenticate = async () => {
    const authEmail = document.getElementById("auth-email").value;
    const authPassword = document.getElementById("auth-password").value;

    const clientFirstMessage = {
        email: authEmail,
        nonce: generateNonce(),
    };

    const serverFirstMessageResp = await fetch(
        `${SERVER_URL}/authenticate/first`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(clientFirstMessage),
        }
    );

    if (!serverFirstMessageResp.ok) {
        alert("Authentication failed");
        return;
    }

    const { iterations, salt, fullNonce } = /** @type {ServerFistMessage} */ (
        await serverFirstMessageResp.json()
    );

    const saltedPassword = await generateSaltedPassword(
        authPassword,
        salt,
        iterations
    );

    const clientKey = await generateClientKey(saltedPassword);

    const storedKey = await generateStoredKey(clientKey);

    const authMessage = generateAuthMessage(
        authEmail,
        fullNonce,
        salt,
        iterations
    );

    const clientSignature = await generateSignature(storedKey, authMessage);

    const base64ClientProof = btoa(
        String.fromCharCode(...xorUint8Arrays(clientKey, clientSignature))
    );

    const serverFinalMessageResp = await fetch(
        `${SERVER_URL}/authenticate/final`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ base64ClientProof, fullNonce }),
        }
    );

    const { base64ServerSignature } =
        /** @type {ServerFinalMessage} */
        (await serverFinalMessageResp.json());

    const decodedServerSignature = new Uint8Array(
        [...atob(base64ServerSignature)].map((c) => c.charCodeAt(0))
    );

    const serverKey = await generateServerKey(saltedPassword);

    const serverSignature = await generateSignature(serverKey);

    if (
        btoa(String.fromCharCode(...decodedServerSignature)) !==
        btoa(String.fromCharCode(...serverSignature))
    ) {
        alert("Authentication failed");

        return;
    }

    alert("Successfully authenticated both client and server");
};

document.getElementById("auth-btn").onclick = authenticate;
