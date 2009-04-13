/* Copyright 2004, 2005, 2006, 2007 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.authentication.encoding;

/**
 * Implementation of the MD4 message digest derived from the RSA Data Security, Inc, MD4 Message-Digest Algorithm.
 *
 * @author Alan Stewart
 */
class Md4 {
    private static final int BLOCK_SIZE = 64;
    private static final int HASH_SIZE = 16;
    private final byte[] buffer = new byte[BLOCK_SIZE];
    private int bufferOffset;
    private long byteCount;
    private int[] state = new int[4];
    private int[] tmp = new int[16];

    Md4() {
        reset();
    }

    public void reset() {
        bufferOffset = 0;
        byteCount = 0;
        state[0] = 0x67452301;
        state[1] = 0xEFCDAB89;
        state[2] = 0x98BADCFE;
        state[3] = 0x10325476;
    }

    public byte[] digest() {
        byte[] resBuf = new byte[HASH_SIZE];
        digest(resBuf, 0, HASH_SIZE);
        return resBuf;
    }

    private void digest(byte[] buffer, int off) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                buffer[off + (i * 4 + j)] = (byte) (state[i] >>> (8 * j));
            }
        }
    }

    private void digest(byte[] buffer, int offset, int len) {
        this.buffer[this.bufferOffset++] = (byte) 0x80;
        int lenOfBitLen = 8;
        int C = BLOCK_SIZE - lenOfBitLen;
        if (this.bufferOffset > C) {
            while (this.bufferOffset < BLOCK_SIZE) {
                this.buffer[this.bufferOffset++] = (byte) 0x00;
            }
            update(this.buffer, 0);
            this.bufferOffset = 0;
        }

        while (this.bufferOffset < C) {
            this.buffer[this.bufferOffset++] = (byte) 0x00;
        }

        long bitCount = byteCount * 8;
        for (int i = 0; i < 64; i += 8) {
            this.buffer[this.bufferOffset++] = (byte) (bitCount >>> (i));
        }

        update(this.buffer, 0);
        digest(buffer, offset);
    }

    public void update(byte[] input, int offset, int length) {
        byteCount += length;
        int todo;
        while (length >= (todo = BLOCK_SIZE - this.bufferOffset)) {
            System.arraycopy(input, offset, this.buffer, this.bufferOffset, todo);
            update(this.buffer, 0);
            length -= todo;
            offset += todo;
            this.bufferOffset = 0;
        }

        System.arraycopy(input, offset, this.buffer, this.bufferOffset, length);
        bufferOffset += length;
    }

    private void update(byte[] block, int offset) {
        for (int i = 0; i < 16; i++) {
            tmp[i] = (block[offset++] & 0xFF) | (block[offset++] & 0xFF) << 8 | (block[offset++] & 0xFF) << 16 | (block[offset++] & 0xFF) << 24;
        }

        int A = state[0];
        int B = state[1];
        int C = state[2];
        int D = state[3];

        A = FF(A, B, C, D, tmp[0], 3);
        D = FF(D, A, B, C, tmp[1], 7);
        C = FF(C, D, A, B, tmp[2], 11);
        B = FF(B, C, D, A, tmp[3], 19);
        A = FF(A, B, C, D, tmp[4], 3);
        D = FF(D, A, B, C, tmp[5], 7);
        C = FF(C, D, A, B, tmp[6], 11);
        B = FF(B, C, D, A, tmp[7], 19);
        A = FF(A, B, C, D, tmp[8], 3);
        D = FF(D, A, B, C, tmp[9], 7);
        C = FF(C, D, A, B, tmp[10], 11);
        B = FF(B, C, D, A, tmp[11], 19);
        A = FF(A, B, C, D, tmp[12], 3);
        D = FF(D, A, B, C, tmp[13], 7);
        C = FF(C, D, A, B, tmp[14], 11);
        B = FF(B, C, D, A, tmp[15], 19);

        A = GG(A, B, C, D, tmp[0], 3);
        D = GG(D, A, B, C, tmp[4], 5);
        C = GG(C, D, A, B, tmp[8], 9);
        B = GG(B, C, D, A, tmp[12], 13);
        A = GG(A, B, C, D, tmp[1], 3);
        D = GG(D, A, B, C, tmp[5], 5);
        C = GG(C, D, A, B, tmp[9], 9);
        B = GG(B, C, D, A, tmp[13], 13);
        A = GG(A, B, C, D, tmp[2], 3);
        D = GG(D, A, B, C, tmp[6], 5);
        C = GG(C, D, A, B, tmp[10], 9);
        B = GG(B, C, D, A, tmp[14], 13);
        A = GG(A, B, C, D, tmp[3], 3);
        D = GG(D, A, B, C, tmp[7], 5);
        C = GG(C, D, A, B, tmp[11], 9);
        B = GG(B, C, D, A, tmp[15], 13);

        A = HH(A, B, C, D, tmp[0], 3);
        D = HH(D, A, B, C, tmp[8], 9);
        C = HH(C, D, A, B, tmp[4], 11);
        B = HH(B, C, D, A, tmp[12], 15);
        A = HH(A, B, C, D, tmp[2], 3);
        D = HH(D, A, B, C, tmp[10], 9);
        C = HH(C, D, A, B, tmp[6], 11);
        B = HH(B, C, D, A, tmp[14], 15);
        A = HH(A, B, C, D, tmp[1], 3);
        D = HH(D, A, B, C, tmp[9], 9);
        C = HH(C, D, A, B, tmp[5], 11);
        B = HH(B, C, D, A, tmp[13], 15);
        A = HH(A, B, C, D, tmp[3], 3);
        D = HH(D, A, B, C, tmp[11], 9);
        C = HH(C, D, A, B, tmp[7], 11);
        B = HH(B, C, D, A, tmp[15], 15);

        state[0] += A;
        state[1] += B;
        state[2] += C;
        state[3] += D;
    }

    private int FF(int a, int b, int c, int d, int x, int s) {
        int t = a + ((b & c) | (~b & d)) + x;
        return t << s | t >>> (32 - s);
    }

    private int GG(int a, int b, int c, int d, int x, int s) {
        int t = a + ((b & (c | d)) | (c & d)) + x + 0x5A827999;
        return t << s | t >>> (32 - s);
    }

    private int HH(int a, int b, int c, int d, int x, int s) {
        int t = a + (b ^ c ^ d) + x + 0x6ED9EBA1;
        return t << s | t >>> (32 - s);
    }
}
