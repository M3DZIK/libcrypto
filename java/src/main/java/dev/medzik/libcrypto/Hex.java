// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

// https://github.com/tink-crypto/tink-java/blob/5cafae05129e08328918c9f44f5b51f8ce7215fa/src/main/java/com/google/crypto/tink/subtle/Hex.java

package dev.medzik.libcrypto;

/**
 * The Hex class is based on source code from the Google Tink project.
 * Google Tink is an open-source cryptographic tool developed by Google.
 * This class contains an implementation of hex encoding/decoding.
 * <br>
 * All operations are compliant with the <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>
 * <br>
 * Original source code implementation can be found here:
 * <a href="https://github.com/tink-crypto/tink-java/blob/5cafae05129e08328918c9f44f5b51f8ce7215fa/src/main/java/com/google/crypto/tink/subtle/Hex.java">
 *  See Google Tink on GitHub
 * </a>
 *
 * @author Google Inc.
 */
public final class Hex {
    private static final String chars = "0123456789abcdef";

    /** Encodes a byte array to hex. */
    public static String encode(byte[] bytes) {
        StringBuilder result = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            // convert to unsigned
            int val = b & 0xff;
            result.append(chars.charAt(val / 16));
            result.append(chars.charAt(val % 16));
        }
        return result.toString();
    }

    /**
     * Decodes a hex string to a byte array.
     * @throws IllegalArgumentException if the input is not hexadecimal
     */
    public static byte[] decode(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Expected a string of even length");
        }
        int size = hex.length() / 2;
        byte[] result = new byte[size];
        for (int i = 0; i < size; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if ((hi == -1) || (lo == -1)) {
                throw new IllegalArgumentException("input is not hexadecimal");
            }
            result[i] = (byte) (16 * hi + lo);
        }
        return result;
    }
}
