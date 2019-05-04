"use strict";

(function (exports) {

    var lookup = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    var reverseLookup = new Uint8Array(256);

    for (var i = 0; i < lookup.length; i++) {
        reverseLookup[lookup.charCodeAt(i)] = i;
    }

    function decodeBase64url(base64url) {
        var base64urlLength = base64url.length;

        var placeHolderLength = base64url.charAt(base64urlLength - 2) === '=' ? 2 : base64url.charAt(base64urlLength - 1) === '=' ? 1 : 0;
        var bufferLength = (base64urlLength * 3 / 4) - placeHolderLength;

        var arrayBuffer = new ArrayBuffer(bufferLength);
        var uint8Array = new Uint8Array(arrayBuffer);

        var j = 0;
        for (var i = 0; i < base64urlLength; i+=4) {
            var tmp0 = reverseLookup[base64url.charCodeAt(i)];
            var tmp1 = reverseLookup[base64url.charCodeAt(i+1)];
            var tmp2 = reverseLookup[base64url.charCodeAt(i+2)];
            var tmp3 = reverseLookup[base64url.charCodeAt(i+3)];

            uint8Array[j++] = (tmp0 << 2) | (tmp1 >> 4);
            uint8Array[j++] = ((tmp1 & 15) << 4) | (tmp2 >> 2);
            uint8Array[j++] = ((tmp2 & 3) << 6) | (tmp3 & 63);
        }

        return arrayBuffer;
    }

    function encodeBase64url(arrayBuffer) {
        var uint8Array = new Uint8Array(arrayBuffer);
        var length = uint8Array.length;
        var base64url = "";

        for (var i = 0; i < length; i+=3) {
            base64url += lookup[uint8Array[i] >> 2];
            base64url += lookup[((uint8Array[i] & 3) << 4) | (uint8Array[i + 1] >> 4)];
            base64url += lookup[((uint8Array[i + 1] & 15) << 2) | (uint8Array[i + 2] >> 6)];
            base64url += lookup[uint8Array[i + 2] & 63];
        }

        switch (length % 3) {
            case 1:
                base64url = base64url.substring(0, base64url.length - 2);
                break;
            case 2:
                base64url = base64url.substring(0, base64url.length - 1);
                break;
        }
        return base64url;
    }

    exports.decodeBase64url = decodeBase64url;
    exports.encodeBase64url = encodeBase64url;

}(typeof exports === 'undefined' ? (this.base64url = {}) : exports));

