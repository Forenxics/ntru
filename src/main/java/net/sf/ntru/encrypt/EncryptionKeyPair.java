/**
 * Copyright (c) 2011, Tim Buktu
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


package net.sf.ntru.encrypt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import net.sf.ntru.arith.IntEuclidean;
import net.sf.ntru.encrypt.EncryptionPrivateKey;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.ProductFormPolynomial;

public class EncryptionKeyPair {
    private EncryptionPrivateKey privateKey;
    private EncryptionPublicKey publicKey;

    public EncryptionKeyPair(EncryptionPrivateKey privateKey, EncryptionPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public EncryptionKeyPair(byte[] encodedKeyPair) {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedKeyPair);
        publicKey = new EncryptionPublicKey(inputStream);
        privateKey = new EncryptionPrivateKey(inputStream);
    }

    public EncryptionKeyPair(InputStream inputStream) {
        publicKey = new EncryptionPublicKey(inputStream);
        privateKey = new EncryptionPrivateKey(inputStream);
    }

    public EncryptionPrivateKey getPrivateKey() {
        return privateKey;
    }

    public EncryptionPublicKey getPublicKey() {
        return publicKey;
    }

    public boolean isValid() {
        return validateKeyPair();
    }

    private boolean validateKeyPair() {
        int n = privateKey.getN();
        int q = privateKey.getQ();
        TernaryPolynomialType polyType = privateKey.getPolyType();

        if (!validatePublicKeys(n, q, polyType)) {
            return false;
        }

        if (!validatePrivatePolynomial(n, polyType)) {
            return false;
        }

        if (!validatePublicPolynomial(n, polyType)) {
            return false;
        }

        return true;
    }

    private boolean validatePublicKeys(int n, int q, TernaryPolynomialType polyType) {
        if (publicKey.getN()!= n) {
            return false;
        }

        if (publicKey.getQ()!= q) {
            return false;
        }

        return true;
    }

    private boolean validatePrivatePolynomial(int n, TernaryPolynomialType polyType) {
        if (polyType == TernaryPolynomialType.SIMPLE) {
            return privateKey.getT().isTernary();
        } else if (polyType == TernaryPolynomialType.PRODUCT) {
            return privateKey.getT() instanceof ProductFormPolynomial;
        }

        return false;
    }

    private boolean validatePublicPolynomial(int n, TernaryPolynomialType polyType) {
        IntegerPolynomial h = publicKey.getH().toIntegerPolynomial();

        if (h.coeffs.length!= n) {
            return false;
        }

        if (!h.isReduced(publicKey.getQ())) {
            return false;
        }

        if (polyType == TernaryPolynomialType.PRODUCT) {
            IntegerPolynomial f = privateKey.getT().toIntegerPolynomial();
            f.mult(3);
            f.coeffs[0] += 1;
            f.modPositive(publicKey.getQ());

            IntegerPolynomial g = f.mult(h, publicKey.getQ());
            int inv9 = IntEuclidean.calculate(9, publicKey.getQ()).x;
            g.mult(inv9);
            g.modCenter(publicKey.getQ());

            return g.isTernary() && g.count(1) == n / 3 && g.count(-1) == n / 3 - 1;
        }

        return true;
    }

    public byte[] getEncoded() {
        if (publicKey == null || privateKey == null) {
            return new byte[0];
        }

        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] privateKeyBytes = privateKey.getEncoded();

        byte[] encodedKeyPair = new byte[publicKeyBytes.length + privateKeyBytes.length];
        System.arraycopy(publicKeyBytes, 0, encodedKeyPair, 0, publicKeyBytes.length);
        System.arraycopy(privateKeyBytes, 0, encodedKeyPair, publicKeyBytes.length, privateKeyBytes.length);

        return encodedKeyPair;
    }

    public void writeTo(OutputStream outputStream) throws IOException {
        outputStream.write(getEncoded());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((privateKey == null)? 0 : privateKey.hashCode());
        result = prime * result + ((publicKey == null)? 0 : publicKey.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null || getClass()!= obj.getClass()) {
            return false;
        }

        EncryptionKeyPair other = (EncryptionKeyPair) obj;

        if (privateKey == null) {
            if (other.privateKey!= null) {
                return false;
            }
        } else if (!privateKey.equals(other.privateKey)) {
            return false;
        }

        if (publicKey == null) {
            if (other.publicKey!= null) {
                return false;
            }
        } else if (!publicKey.equals(other.publicKey)) {
            return false;
        }

        return true;
    }
}
