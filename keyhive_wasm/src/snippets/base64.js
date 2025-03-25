window.uint8ArrayToBase64 = (bytes) => {
    const binStr = String.fromCharCode(...bytes);
    return btoa(binStr);
};

window.base64ToUint8Array = (base64Str) => {
    const decoded = atob(base64Str);
    const bytes = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i++) {
        bytes[i] = decoded.charCodeAt(i);
    }
    return bytes;
};
