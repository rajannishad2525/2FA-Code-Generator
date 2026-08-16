let secret = "";
let timerInterval;

function base32ToBytes(base32) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    base32 = base32
        .replace(/\s/g, "")
        .replace(/=+$/, "")
        .toUpperCase();

    let bits = "";
    let bytes = [];

    for (let char of base32) {
        const value = alphabet.indexOf(char);

        if (value === -1) {
            throw new Error("Invalid Base32 secret");
        }

        bits += value.toString(2).padStart(5, "0");
    }

    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(
            parseInt(bits.substring(i, i + 8), 2)
        );
    }

    return new Uint8Array(bytes);
}

async function generateTOTP(secret) {
    const keyBytes = base32ToBytes(secret);

    const counter = Math.floor(
        Date.now() / 1000 / 30
    );

    const counterBytes = new ArrayBuffer(8);
    const view = new DataView(counterBytes);

    view.setUint32(
        0,
        Math.floor(counter / 4294967296)
    );

    view.setUint32(
        4,
        counter >>> 0
    );

    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        {
            name: "HMAC",
            hash: "SHA-1"
        },
        false,
        ["sign"]
    );

    const hash = await crypto.subtle.sign(
        "HMAC",
        cryptoKey,
        counterBytes
    );

    const hashBytes = new Uint8Array(hash);

    const offset =
        hashBytes[hashBytes.length - 1] & 15;

    const binary =
        ((hashBytes[offset] & 127) << 24) |
        ((hashBytes[offset + 1] & 255) << 16) |
        ((hashBytes[offset + 2] & 255) << 8) |
        (hashBytes[offset + 3] & 255);

    const otp =
        (binary % 1000000)
        .toString()
        .padStart(6, "0");

    return otp;
}

function startTOTP() {
    secret = document
        .getElementById("secretKey")
        .value
        .trim()
        .replace(/\s/g, "")
        .toUpperCase();

    if (!secret) {
        document.getElementById("message").textContent =
            "Please enter a secret key.";

        document.getElementById("message").style.color =
            "red";

        return;
    }

    document.getElementById("message").textContent =
        "Generating code...";

    document.getElementById("message").style.color =
        "blue";

    updateTOTP();

    clearInterval(timerInterval);

    timerInterval = setInterval(
        updateTOTP,
        1000
    );
}

async function updateTOTP() {
    try {
        const code =
            await generateTOTP(secret);

        document.getElementById("code").textContent =
            code;

        const remaining =
            30 - (Math.floor(Date.now() / 1000) % 30);

        document.getElementById("timer").textContent =
            remaining;

        document.getElementById("message").textContent =
            "2FA code generated successfully.";

        document.getElementById("message").style.color =
            "green";

    } catch (error) {
        document.getElementById("code").textContent =
            "------";

        document.getElementById("message").textContent =
            "Invalid secret key.";

        document.getElementById("message").style.color =
            "red";

        clearInterval(timerInterval);
    }
}
