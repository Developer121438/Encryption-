// ========================================
// FILE ENCRYPTOR
// AES-256-GCM + PBKDF2-SHA-256
// ========================================


// ========================================
// HTML ELEMENTS
// ========================================

const fileInput = document.getElementById("document");
const passwordInput = document.getElementById("secret");

const encryptBtn = document.getElementById("en-Btn");
const decryptBtn = document.getElementById("de-Btn");

const progressBar = document.querySelector(".fill");
const progressText = document.querySelector(".range span");

const downloadBtn = document.getElementById("downloadBtn");


// ========================================
// CONFIGURATION
// ========================================

const PBKDF2_ITERATIONS = 600000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

// Our encrypted file identifier
const FILE_MAGIC = "FENC1";


// ========================================
// DOWNLOAD VARIABLES
// ========================================

let downloadBlob = null;
let downloadFilename = "";


// ========================================
// PROGRESS BAR
// ========================================

function updateProgress(percent) {

    progressBar.style.width = `${percent}%`;

    progressText.textContent = `${Math.round(percent)}%`;
}


// ========================================
// RESET DOWNLOAD
// ========================================

function resetDownload() {

    downloadBlob = null;
    downloadFilename = "";

    downloadBtn.hidden = true;
}


// ========================================
// PASSWORD → AES KEY
// ========================================

async function deriveKey(password, salt) {

    const encoder = new TextEncoder();

    const passwordBytes = encoder.encode(password);


    // Import password as a PBKDF2 key
    const passwordKey = await crypto.subtle.importKey(
        "raw",
        passwordBytes,
        "PBKDF2",
        false,
        ["deriveKey"]
    );


    // Derive AES-256 key
    const aesKey = await crypto.subtle.deriveKey(

        {
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },

        passwordKey,

        {
            name: "AES-GCM",
            length: 256
        },

        false,

        ["encrypt", "decrypt"]
    );


    return aesKey;
}


// ========================================
// CONVERT BYTES → BASE64
// ========================================

function bytesToBase64(bytes) {

    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}


// ========================================
// CONVERT BASE64 → BYTES
// ========================================

function base64ToBytes(base64) {

    const binary = atob(base64);

    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}


// ========================================
// CREATE ENCRYPTED FILE
// ========================================

function createEncryptedFile(headerBytes, encryptedData) {

    const magicBytes = new TextEncoder().encode(FILE_MAGIC);

    const headerLength = new Uint8Array(4);

    const view = new DataView(headerLength.buffer);

    view.setUint32(0, headerBytes.length);


    return new Blob(

        [
            magicBytes,
            headerLength,
            headerBytes,
            new Uint8Array(encryptedData)
        ],

        {
            type: "application/octet-stream"
        }
    );
}


// ========================================
// PREPARE DOWNLOAD
// ========================================

function prepareDownload(blob, filename) {

    downloadBlob = blob;
    downloadFilename = filename;

    downloadBtn.hidden = false;
}


// ========================================
// DOWNLOAD BUTTON
// ========================================

downloadBtn.addEventListener("click", function () {

    if (!downloadBlob) {
        return;
    }


    const url = URL.createObjectURL(downloadBlob);

    const link = document.createElement("a");

    link.href = url;
    link.download = downloadFilename;

    document.body.appendChild(link);

    link.click();

    link.remove();

    URL.revokeObjectURL(url);
});


// ========================================
// GET USER INPUT
// ========================================

function getInput() {

    const file = fileInput.files[0];

    if (!file) {

        alert("Please select a file.");

        return null;
    }


    const password = passwordInput.value;

    if (!password) {

        alert("Please enter a password.");

        return null;
    }


    if (password.length < 8) {

        alert("Password must contain at least 8 characters.");

        return null;
    }


    return {
        file,
        password
    };
}


// ========================================
// ENCRYPT
// ========================================

encryptBtn.addEventListener("click", async function () {

    const input = getInput();

    if (!input) {
        return;
    }


    const { file, password } = input;


    try {

        // --------------------------------
        // Prepare interface
        // --------------------------------

        encryptBtn.disabled = true;
        decryptBtn.disabled = true;

        resetDownload();

        updateProgress(0);


        // --------------------------------
        // Read file
        // --------------------------------

        const fileData = await file.arrayBuffer();

        updateProgress(20);


        // --------------------------------
        // Generate random salt
        // --------------------------------

        const salt = crypto.getRandomValues(
            new Uint8Array(SALT_LENGTH)
        );

        updateProgress(30);


        // --------------------------------
        // Generate random IV
        // --------------------------------

        const iv = crypto.getRandomValues(
            new Uint8Array(IV_LENGTH)
        );

        updateProgress(35);


        // --------------------------------
        // Create AES-256 key
        // --------------------------------

        const key = await deriveKey(
            password,
            salt
        );

        updateProgress(50);


        // --------------------------------
        // Create metadata
        // --------------------------------

        const metadata = {

            magic: FILE_MAGIC,

            version: 1,

            originalName: file.name,

            originalType: file.type || "application/octet-stream",

            originalSize: file.size,

            salt: bytesToBase64(salt),

            iv: bytesToBase64(iv)
        };


        // Convert metadata to bytes
        const encoder = new TextEncoder();

        const metadataBytes = encoder.encode(
            JSON.stringify(metadata)
        );


        // --------------------------------
        // Encrypt
        // --------------------------------

        const encryptedData = await crypto.subtle.encrypt(

            {
                name: "AES-GCM",

                iv: iv,

                // Authenticate the metadata
                additionalData: metadataBytes
            },

            key,

            fileData
        );

        updateProgress(80);


        // --------------------------------
        // Build final encrypted file
        // --------------------------------

        const encryptedFile = createEncryptedFile(
            metadataBytes,
            encryptedData
        );


        updateProgress(100);


        // --------------------------------
        // Prepare download
        // --------------------------------

        prepareDownload(
            encryptedFile,
            file.name + ".enc"
        );


    } catch (error) {

        console.error("Encryption error:", error);

        alert("Encryption failed.");

        updateProgress(0);

    } finally {

        encryptBtn.disabled = false;
        decryptBtn.disabled = false;
    }

});


// ========================================
// DECRYPT
// ========================================

decryptBtn.addEventListener("click", async function () {

    const input = getInput();

    if (!input) {
        return;
    }


    const { file, password } = input;


    try {

        // --------------------------------
        // Prepare interface
        // --------------------------------

        encryptBtn.disabled = true;
        decryptBtn.disabled = true;

        resetDownload();

        updateProgress(0);


        // --------------------------------
        // Read encrypted file
        // --------------------------------

        const fileBytes = new Uint8Array(
            await file.arrayBuffer()
        );

        updateProgress(20);


        // --------------------------------
        // Check minimum size
        // --------------------------------

        if (fileBytes.length < 9) {

            throw new Error(
                "File is too small to be a valid encrypted file."
            );
        }


        // --------------------------------
        // Read MAGIC
        // --------------------------------

        const magicBytes = fileBytes.slice(0, 5);

        const magic = new TextDecoder().decode(
            magicBytes
        );


        if (magic !== FILE_MAGIC) {

            throw new Error(
                "This is not a file created by this encryption tool."
            );
        }


        updateProgress(25);


        // --------------------------------
        // Read metadata length
        // --------------------------------

        const lengthBytes = fileBytes.slice(5, 9);

        const lengthView = new DataView(
            lengthBytes.buffer,
            lengthBytes.byteOffset,
            lengthBytes.byteLength
        );

        const metadataLength = lengthView.getUint32(0);


        // --------------------------------
        // Validate metadata length
        // --------------------------------

        if (
            metadataLength <= 0 ||
            9 + metadataLength >= fileBytes.length
        ) {

            throw new Error(
                "Invalid encrypted file structure."
            );
        }


        // --------------------------------
        // Extract metadata
        // --------------------------------

        const metadataBytes = fileBytes.slice(
            9,
            9 + metadataLength
        );


        const metadataText = new TextDecoder().decode(
            metadataBytes
        );


        const metadata = JSON.parse(
            metadataText
        );


        // --------------------------------
        // Validate metadata
        // --------------------------------

        if (
            metadata.magic !== FILE_MAGIC ||
            metadata.version !== 1
        ) {

            throw new Error(
                "Unsupported encrypted file version."
            );
        }


        updateProgress(35);


        // --------------------------------
        // Recover SALT
        // --------------------------------

        const salt = base64ToBytes(
            metadata.salt
        );


        // --------------------------------
        // Recover IV
        // --------------------------------

        const iv = base64ToBytes(
            metadata.iv
        );


        // --------------------------------
        // Extract encrypted data
        // --------------------------------

        const encryptedData = fileBytes.slice(
            9 + metadataLength
        );


        updateProgress(40);


        // --------------------------------
        // Recreate AES key
        // --------------------------------

        const key = await deriveKey(
            password,
            salt
        );


        updateProgress(55);


        // --------------------------------
        // Decrypt
        // --------------------------------

        const decryptedData = await crypto.subtle.decrypt(

            {
                name: "AES-GCM",

                iv: iv,

                additionalData: metadataBytes
            },

            key,

            encryptedData
        );


        updateProgress(85);


        // --------------------------------
        // Restore original filename
        // --------------------------------

        const originalFilename =
            metadata.originalName ||
            "decrypted-file";


        // --------------------------------
        // Restore original MIME type
        // --------------------------------

        const originalType =
            metadata.originalType ||
            "application/octet-stream";


        // --------------------------------
        // Create decrypted file
        // --------------------------------

        const decryptedFile = new Blob(

            [decryptedData],

            {
                type: originalType
            }
        );


        updateProgress(100);


        // --------------------------------
        // Prepare download
        // --------------------------------

        prepareDownload(
            decryptedFile,
            originalFilename
        );


    } catch (error) {

        console.error("Decryption error:", error);

        alert(
            "Decryption failed.\n\n" +
            "The password may be incorrect, " +
            "or the file may be damaged or invalid."
        );

        updateProgress(0);

    } finally {

        encryptBtn.disabled = false;
        decryptBtn.disabled = false;
    }

});