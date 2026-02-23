import {
    generateAuthMessage,
    generateNonce,
    generateSignature,
    generateStoredKey,
    xorUint8Arrays,
} from "../crypto/index.js";
import express, { json } from "express";

const app = express();
const PORT = 3000;

app.use(json());

app.use((_, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "http://localhost:5173");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    next();
});

const db = {
    users: {},
    sessions: {},
};

app.post("/register", (req, res) => {
    const body = req.body;

    db.users[body.registerEmail] = body;

    return res.json({ received: body });
});

/**
 * @typedef {Object} ClientFirstMessage
 * @property {string} email
 * @property {string} nonce
 */
app.post("/authenticate/first", (req, res) => {
    const { email, nonce: clientNonce } = /** @type {ClientFirstMessage} */ (
        req.body
    );

    const serverNonce = generateNonce();

    const fullNonce = clientNonce + serverNonce;

    const serverFirstMessage = {
        iterations: db.users[email].iterations,
        salt: db.users[email].salt,
        fullNonce,
    };

    db.sessions[fullNonce] = {
        email,
    };

    return res.json(serverFirstMessage);
});

/**
 * @typedef {Object} ClientFinalMessage
 * @property {string} base64ClientProof
 * @property {string} fullNonce
 *
 * @typedef {Object} DbUser
 * @property {number} iterations
 * @property {string} salt
 * @property {string} base64StoredKey
 * @property {string} base64ServerKey
 */
app.post("/authenticate/final", async (req, res) => {
    const { base64ClientProof, fullNonce } = /** @type {ClientFinalMessage} */ (
        req.body
    );

    const email = /** @type {string} */ (db.sessions[fullNonce].email);

    const { iterations, salt, base64ServerKey, base64StoredKey } =
        /** @type {DbUser} */ (db.users[email]);

    const authMessage = generateAuthMessage(email, fullNonce, salt, iterations);

    const decodedClientProof = new Uint8Array(
        [...atob(base64ClientProof)].map((c) => c.charCodeAt(0))
    );

    const decodedStoredKey = new Uint8Array(
        [...atob(base64StoredKey)].map((c) => c.charCodeAt(0))
    );

    const clientSignature = await generateSignature(
        decodedStoredKey,
        authMessage
    );

    const recoveredClientKey = xorUint8Arrays(
        clientSignature,
        decodedClientProof
    );

    const storedKeyFromRecoveredClientKey =
        await generateStoredKey(recoveredClientKey);

    if (
        btoa(String.fromCharCode(...decodedStoredKey)) !==
        btoa(String.fromCharCode(...storedKeyFromRecoveredClientKey))
    ) {
        console.log("Client failed to authenticate");
        //TODO: Return some bad response
    }

    console.log("Client successfully authenticated");

    const decodedServerKey = new Uint8Array(
        [...atob(base64ServerKey)].map((c) => c.charCodeAt(0))
    );

    const serverSignature = await generateSignature(decodedServerKey)

    const base64ServerSignature = btoa(String.fromCharCode(...serverSignature))

    const serverFinalMessage = {
        base64ServerSignature
    }

    return res.json(serverFinalMessage)
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
