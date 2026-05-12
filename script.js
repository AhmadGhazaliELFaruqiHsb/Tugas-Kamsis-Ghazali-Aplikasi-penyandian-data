// --- LOGIKA KRIPTOGRAFI MANUAL (NO LIBRARY) ---

// 1. S-BOX & P-BOX (SUBSTITUSI & PERMUTASI)
const S_BOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) S_BOX[i] = (i * 31 + 17) % 256;
const P_BOX = [2, 0, 3, 1]; 

function rotl8(val, shift) { return ((val << shift) | (val >>> (8 - shift))) & 0xFF; }

function feistelFunction(rightHalf, subKey) {
    let out = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        out[i] = rotl8(S_BOX[rightHalf[i] ^ subKey[i]], 3);
    }
    let permuted = new Uint8Array(4);
    for (let i = 0; i < 4; i++) permuted[i] = out[P_BOX[i]];
    return permuted;
}

// 2. ENKRIPSI/DEKRIPSI BLOK (16 ROUNDS)
function encryptBlock(block, key) {
    let L = block.slice(0, 4), R = block.slice(4, 8);
    for (let i = 0; i < 16; i++) {
        let subKey = new Uint8Array([key[i%8], key[(i+1)%8], key[(i+2)%8], key[(i+3)%8]]);
        let f = feistelFunction(R, subKey);
        let nextR = new Uint8Array(4);
        for(let j=0; j<4; j++) nextR[j] = L[j] ^ f[j];
        L = R; R = nextR;
    }
    let out = new Uint8Array(8); out.set(R, 0); out.set(L, 4);
    return out;
}

function decryptBlock(block, key) {
    let R = block.slice(0, 4), L = block.slice(4, 8);
    for (let i = 15; i >= 0; i--) {
        let subKey = new Uint8Array([key[i%8], key[(i+1)%8], key[(i+2)%8], key[(i+3)%8]]);
        let f = feistelFunction(L, subKey);
        let nextL = new Uint8Array(4);
        for(let j=0; j<4; j++) nextL[j] = R[j] ^ f[j];
        R = L; L = nextL;
    }
    let out = new Uint8Array(8); out.set(L, 0); out.set(R, 4);
    return out;
}

// 3. CBC MODE
function encryptCBC(dataBytes, key) {
    let padLen = 8 - (dataBytes.length % 8);
    let padded = new Uint8Array(dataBytes.length + padLen);
    padded.set(dataBytes);
    for (let i = dataBytes.length; i < padded.length; i++) padded[i] = padLen;

    let iv = window.crypto.getRandomValues(new Uint8Array(8));
    let ciphertext = new Uint8Array(iv.length + padded.length);
    ciphertext.set(iv);

    let prev = iv;
    for (let i = 0; i < padded.length; i += 8) {
        let block = padded.slice(i, i + 8);
        for (let j = 0; j < 8; j++) block[j] ^= prev[j];
        let encBlock = encryptBlock(block, key);
        ciphertext.set(encBlock, iv.length + i);
        prev = encBlock;
    }
    return ciphertext;
}

function decryptCBC(cipherBytes, key) {
    if (cipherBytes.length < 16 || cipherBytes.length % 8 !== 0) throw new Error("Ciphertext rusak/tidak valid.");
    let iv = cipherBytes.slice(0, 8);
    let data = cipherBytes.slice(8);
    let plainPadded = new Uint8Array(data.length);

    let prev = iv;
    for (let i = 0; i < data.length; i += 8) {
        let block = data.slice(i, i + 8);
        let decBlock = decryptBlock(block, key);
        for (let j = 0; j < 8; j++) decBlock[j] ^= prev[j];
        plainPadded.set(decBlock, i);
        prev = block;
    }
    let padLen = plainPadded[plainPadded.length - 1];
    if (padLen < 1 || padLen > 8) throw new Error("Kunci salah atau padding error.");
    return plainPadded.slice(0, plainPadded.length - padLen);
}

// 4. BASE64 MANUAL -
const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function bytesToBase64(bytes) {
    let result = '';
    for (let i = 0; i < bytes.length; i += 3) {
        let b1 = bytes[i], b2 = bytes[i+1] || 0, b3 = bytes[i+2] || 0;
        result += BASE64_CHARS[b1 >> 2];
        result += BASE64_CHARS[((b1 & 3) << 4) | (b2 >> 4)];
        result += i + 1 < bytes.length ? BASE64_CHARS[((b2 & 15) << 2) | (b3 >> 6)] : '=';
        result += i + 2 < bytes.length ? BASE64_CHARS[b3 & 63] : '=';
    }
    return result;
}

function base64ToBytes(base64) {
    let s = base64.replace(/[^A-Za-z0-9+/]/g, ''); //
    let bytes = new Uint8Array(Math.floor((s.length * 3) / 4));
    for (let i = 0, j = 0; i < s.length; i += 4) {
        let e1 = BASE64_CHARS.indexOf(s[i]), e2 = BASE64_CHARS.indexOf(s[i+1]);
        let e3 = i+2 < s.length ? BASE64_CHARS.indexOf(s[i+2]) : -1;
        let e4 = i+3 < s.length ? BASE64_CHARS.indexOf(s[i+3]) : -1;
        bytes[j++] = (e1 << 2) | (e2 >> 4);
        if (e3 !== -1) bytes[j++] = ((e2 & 15) << 4) | (e3 >> 2);
        if (e4 !== -1) bytes[j++] = ((e3 & 3) << 6) | e4;
    }
    return bytes;
}


// --- LOGIKA UI & PENANGANAN FILE ---
let currentMode = 'encrypt';
let imageBase64Data = "";
let txtFileContent = "";

function switchMode(mode) {
    currentMode = mode;
    document.getElementById('tabEncrypt').className = mode === 'encrypt' ? 'tab-btn active' : 'tab-btn';
    document.getElementById('tabDecrypt').className = mode === 'decrypt' ? 'tab-btn active' : 'tab-btn';
    document.getElementById('btnAction').innerText = mode === 'encrypt' ? '🔒 EKSEKUSI ENKRIPSI' : '🔓 EKSEKUSI DEKRIPSI';
    
    document.getElementById('outputArea').innerText = "Hasil akan muncul di sini...";
    document.getElementById('outputImage').style.display = 'none';
    document.getElementById('downloadGroup').style.display = 'none';

    if (mode === 'decrypt') {
        document.getElementById('inputType').value = 'text';
    }
    toggleInput();
}

function toggleInput() {
    let type = document.getElementById('inputType').value;
    
    if (currentMode === 'decrypt' && type === 'image') {
        document.getElementById('textInputGroup').style.display = 'block';
        document.getElementById('fileInputGroup').style.display = 'none';
        document.getElementById('textInputLabel').innerText = "3. Paste Teks Sandi (Gambar) di sini:";
    } else {
        document.getElementById('textInputGroup').style.display = type === 'text' ? 'block' : 'none';
        document.getElementById('fileInputGroup').style.display = type === 'image' ? 'block' : 'none';
        document.getElementById('textInputLabel').innerText = "3. Masukkan Pesan:";
    }
    
    document.getElementById('txtFileInputGroup').style.display = type === 'txt' ? 'block' : 'none';
}

function togglePasswordVisibility() {
    const passwordInput = document.getElementById('secretKey');
    const toggleBtn = document.getElementById('togglePassword');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleBtn.innerText = '👁️‍🗨️'; 
    } else {
        passwordInput.type = 'password';
        toggleBtn.innerText = '👁️'; 
    }
}

document.getElementById('inputFile').addEventListener('change', function(e) {
    let file = e.target.files[0];
    if (!file) return;
    let reader = new FileReader();
    reader.onload = function(event) {
        imageBase64Data = event.target.result;
        let preview = document.getElementById('imagePreview');
        preview.src = imageBase64Data;
        preview.style.display = 'block';
    };
    reader.readAsDataURL(file);
});

document.getElementById('inputTxtFile').addEventListener('change', function(e) {
    let file = e.target.files[0];
    if (!file) return;
    let reader = new FileReader();
    reader.onload = function(event) {
        txtFileContent = event.target.result;
    };
    reader.readAsText(file);
});

function processData() {
    let rawKey = document.getElementById('secretKey').value;
    if (!rawKey) return alert("Kunci rahasia tidak boleh kosong!");
    
    let keyStr = rawKey.padEnd(8, '0').substring(0, 8);
    let keyBytes = new TextEncoder().encode(keyStr);
    
    let type = document.getElementById('inputType').value;
    let outputArea = document.getElementById('outputArea');
    let outputImage = document.getElementById('outputImage');
    
    outputArea.innerText = "⏳ Memproses...";
    outputImage.style.display = 'none';

    setTimeout(() => {
        try {
            if (type === 'text' || (type === 'image' && currentMode === 'decrypt')) {
                let input = document.getElementById('inputText').value;
                if (!input) return alert("Kotak pesan tidak boleh kosong!");
                
                if (currentMode === 'encrypt') {
                    let enc = encryptCBC(new TextEncoder().encode(input), keyBytes);
                    outputArea.innerText = bytesToBase64(enc);
                } else {
                    let dec = decryptCBC(base64ToBytes(input), keyBytes);
                    let decryptedStr = new TextDecoder().decode(dec);
                    
                    if (decryptedStr.startsWith('data:image/')) {
                        outputArea.innerText = "✅ Gambar berhasil didekripsi! Lihat di bawah.";
                        outputImage.src = decryptedStr;
                        outputImage.style.display = 'block';
                    } else {
                        outputArea.innerText = decryptedStr;
                    }
                }
            } 
            else if (type === 'image' && currentMode === 'encrypt') {
                if (!imageBase64Data) return alert("Pilih gambar terlebih dahulu!");
                let enc = encryptCBC(new TextEncoder().encode(imageBase64Data), keyBytes);
                outputArea.innerText = bytesToBase64(enc);
            } 
            else if (type === 'txt') {
                if (currentMode === 'encrypt') {
                    if (!txtFileContent) return alert("Pilih file teks terlebih dahulu!");
                    let enc = encryptCBC(new TextEncoder().encode(txtFileContent), keyBytes);
                    outputArea.innerText = bytesToBase64(enc);
                } else {
                    let input = txtFileContent || document.getElementById('inputText').value;
                    if (!input) return alert("Unggah file Ciphertext (.txt) atau paste di kotak pesan!");
                    
                    let dec = decryptCBC(base64ToBytes(input), keyBytes);
                    outputArea.innerText = new TextDecoder().decode(dec);
                }
            }
            
            document.getElementById('downloadGroup').style.display = 'flex';
            
        } catch (e) {
            outputArea.innerText = "ERROR: " + e.message + "\n\nPastikan Kunci benar dan format ciphertext utuh.";
            document.getElementById('downloadGroup').style.display = 'none';
        }
    }, 50);
}

function copyOutput() {
    let outputArea = document.getElementById('outputArea');
    if (!outputArea.innerText || outputArea.innerText.includes("ERROR")) return alert("Tidak ada output yang valid!");
    
    navigator.clipboard.writeText(outputArea.innerText).then(() => {
        alert("Berhasil disalin ke clipboard!");
    });
}

function downloadOutput() {
    let outputArea = document.getElementById('outputArea');
    if (!outputArea.innerText || outputArea.innerText.includes("ERROR")) return alert("Tidak ada output yang valid!");
    
    let blob = new Blob([outputArea.innerText], { type: "text/plain" });
    let link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = currentMode === 'encrypt' ? "hasil_enkripsi.txt" : "hasil_dekripsi.txt";
    link.click();
}
