package cs490midterm;

/**
 *
 * @author: John Paul Smith CS490 Cryptography - Keene State College
 *
 * DES.java
 *
 * DES.java provides access to encryption and decryption functions using the
 * standard DES algorithm. Only two public methods are provided:'encryptMessage'
 * and 'decryptMessage'. Any methods calling either encryptMessage or
 * decryptMessage should pass as parameters the message as ASCII and the
 * appropriate key as a hexadecimal String. The calling functions are
 * responsible for passing the appropriate matching keys and messages. These two
 * methods take in ASCII text and return ASCII text. All conversion of text to
 * byte/bit representation is handled internally by DES.java.
 *
 * The basic principle for encryption/decryption works as follows:
 *
 * Break the String 'message' into 8-byte (64-bit) blocks. Encrypt/decrypt each
 * block according to the key schedule. Concatenate the blocks together into a
 * String, then return the String. The last block (or only block, if the message
 * is less than 8 bytes) will likely be less than 8 bytes. This block will
 * receive the appropriate padding to successfully traverse the algorithm. I use
 * an external method, Utils.stripNulls to remove this padding.
 *
 * Internally, all ASCII text is parsed into arrays of bytes, which themselves
 * represent arrays of bits. For example, the ASCII text String "a" can be
 * treated as decimal value 97. 97 is represented as 01100001 in binary
 * notation. This program will treat this representation as a byte array such
 * that its values are: {0,1,1,0,0,0,0,1}.
 */
import java.math.BigInteger;
import java.util.HashMap;

public class DES {

    /**
     * Encrypt an ASCII String representation of a plaintext message.
     *
     * @param message the String representation of the message to encrypt
     * @param k the String representation of the 64-bit key used by DES
     * @return a String representation of message, encrypted using DES
     */
    public static String encryptMessage(String message, String k) {

        if (k.length() < 16) {

            throw new java.lang.IllegalArgumentException("Key must be 64-bit");
        }

        byte[] key = hexStringTo64BitBinaryArray(k);

        String cipherText = "";

        for (int x = 0; x < message.length(); x += 8) {

            byte[] i;

            if ((x + 8) >= message.length()) {

                i = binArray64(message.substring(x));

            } else {

                i = binArray64(message.substring(x, x + 8));
            }

            /**
             * 64-bit block.
             */
            byte[] c = encrypt(i, key);

            String cipherBinString = intArrayToString(c);

            String h = (new BigInteger(cipherBinString, 2)).toString(16);

            cipherText += Utils.hexToASCII(h);
        }

        return cipherText;
    }

    /**
     * Decrypt an ASCII String representation of a ciphertext message.
     *
     * @param message the String representation of the message to encrypt
     * @param k the String representation of the 64-bit key used by DES
     * @return String representation of message, decrypted using DES
     */
    public static String decryptMessage(String message, String k) {

        byte[] key = hexStringTo64BitBinaryArray(k);

        String plainText = "";

        for (int x = 0; x < message.length(); x += 8) {

            byte[] i;

            if ((x + 8) >= message.length()) {
                i = binArray64(message.substring(x));
            } else {
                i = binArray64(message.substring(x, x + 8));
            }

            byte[] d = decrypt(i, key);

            String cipherBinString = intArrayToString(d);

            String h = (new BigInteger(cipherBinString, 2)).toString(16);

            plainText += Utils.hexToASCII(h);
        }

        return plainText;
    }

    /**
     * Encrypt a 64-bit plaintext block represented as a byte[] using a 64-bit
     * key, also represented as a 64-bit byte[].
     *
     * @param message the 64-bit block of plaintext to encrypt
     * @param key the 64-bit key used to encrypt the plaintext
     * @return a byte[] representation of the resulting ciphertext
     */
    private static byte[] encrypt(byte[] message, byte[] key) {

        /**
         * Generates 16 individual 48-bit round keys.
         */
        byte[][] roundKeys = genKeys(key);

        /**
         * Initial permutation is the input for the first round.
         */
        byte[] i = IP(message);

        for (int x = 0; x < roundKeys.length; ++x) {

            i = round(i, roundKeys[x]);

            /*
             * Uncomment this block to print out the individual round results.
             *
             System.out.println("R" + (x + 1) + " -- Key: " 
             + (new BigInteger(intArrayToString(roundKeys[x]), 2)).toString(16)
             + "  Output: " 
             + (new BigInteger(intArrayToString(i), 2)).toString(16));
             */
        }

        return FP(swapLeftAndRight(i));
    }

    /**
     * Decrypt a 64-bit ciphertext block represented as a byte[] using a 64-bit
     * key, also represented as a 64-bit byte[].
     *
     * @param cipherText the 64-bit block of ciphertext to decrypt
     * @param key the 64-bit key used to decrypt the ciphertext
     * @return a byte[] representation of the resulting plainttext
     */
    private static byte[] decrypt(byte[] cipherText, byte[] key) {

        byte[][] roundKeys = genKeys(key);
        byte[] i = (IP(cipherText));

        for (int x = roundKeys.length - 1; x >= 0; --x) {

            i = round(i, roundKeys[x]);
        }

        return FP(swapLeftAndRight(i));
    }

    /**
     * A single round of the block cipher using a 32-bit input and 48-bit key.
     *
     * @param roundInput the 32-bit input to the round
     * @param roundKey the 48-bit key for this round
     * @return the 64-bit result of this round
     */
    private static byte[] round(byte[] roundInput, byte[] roundKey) {

        byte[] L = new byte[32],
                R = new byte[32];

        System.arraycopy(roundInput, 0, L, 0, 32);
        System.arraycopy(roundInput, 32, R, 0, 32);

        return merge(R, xOR(L, P(S(xOR(E(R), roundKey)))));
    }

    /**
     * The initial permutation table and the first step of the cipher.
     *
     * @param i the 64-bit block to permute
     * @return the permutation of i as per the specified table
     */
    private static byte[] IP(byte[] i) {

        final int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        byte[] ip = new byte[64];

        for (int x = 0; x < i.length; ++x) {
            ip[x] = i[IP[x] - 1];
        }

        return ip;
    }

    /**
     * The final permutation table and final step of the cipher.
     *
     * @param i the 64-bit block to permute
     * @return the permutation of i as per the specified table
     */
    private static byte[] FP(byte[] i) {

        /**
         * aka IP-inverse
         */
        final int[] FP = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };

        byte[] fp = new byte[64];

        for (int x = 0; x < i.length; ++x) {

            fp[x] = i[FP[x] - 1];
        }

        return fp;
    }

    /**
     * Permuted choice 1. This creates a 56-bit key out of the original 64-bit
     * key. Every 8th bit of the input will not be used in the result.
     *
     * @param i the 64-bit key
     * @return a 56-bit permutation of i as per the specified table
     */
    private static byte[] PC1(byte[] i) {

        final int PC1[] = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };

        byte[] p = new byte[56];

        for (int x = 0; x < p.length; ++x) {

            p[x] = i[PC1[x] - 1];
        }

        return p;
    }

    /**
     * Permuted choice 2. This takes in a 56-bit input and returns a 48-bit
     * permutation to create a key for each round of the cipher.
     *
     * @param i the 56-bit input
     * @return the 48-bit permuted result as per the specified table
     */
    private static byte[] PC2(byte[] i) {

        final int PC2[] = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };

        byte[] p = new byte[48];

        for (int x = 0; x < p.length; ++x) {

            p[x] = i[PC2[x] - 1];
        }

        return p;
    }

    /**
     * Merge two arbitrarily-sized byte arrays into a third array.
     *
     * @param a the first byte array to merge with b
     * @param b the second byte array to merge with a
     * @return the byte array that is the concatenation of a and b
     */
    private static byte[] merge(byte[] a, byte[] b) {

        byte[] c = new byte[a.length + b.length];

        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);

        return c;
    }

    /**
     * Perform a wrap-around shift of the indices of a byte array.
     *
     * @param i the array to perform the shift on
     * @param n the number of places to shift each element of i
     * @return the shifted byte array
     */
    private static byte[] leftShift(byte[] i, int n) {

        int b = (n % i.length);
        byte[] s = new byte[i.length];

        System.arraycopy(i, b, s, 0, (s.length - b));
        System.arraycopy(i, 0, s, (s.length - b), b);

        return s;
    }

    /**
     * Generate the 48-bit keys for each round of the cipher.
     *
     * @param k the original 64-bit key
     * @return an array of 48-bit keys represented as byte[]
     */
    private static byte[][] genKeys(byte[] k) {

        /**
         * Create a key schedule using a round number mapped to the number of
         * bits to shift each round.
         */
        HashMap<Integer, Integer> keySchedule = new HashMap(16);

        keySchedule.put(1, 1);
        keySchedule.put(2, 1);
        keySchedule.put(3, 2);
        keySchedule.put(4, 2);
        keySchedule.put(5, 2);
        keySchedule.put(6, 2);
        keySchedule.put(7, 2);
        keySchedule.put(8, 2);
        keySchedule.put(9, 1);
        keySchedule.put(10, 2);
        keySchedule.put(11, 2);
        keySchedule.put(12, 2);
        keySchedule.put(13, 2);
        keySchedule.put(14, 2);
        keySchedule.put(15, 2);
        keySchedule.put(16, 1);

        final int NUM_KEYS = 16;

        byte[] k56 = PC1(k);

        byte[][] roundKeys = new byte[16][48];

        byte[] L = new byte[28],
                R = new byte[28];

        System.arraycopy(k56, 0, L, 0, 28);
        System.arraycopy(k56, 28, R, 0, 28);

        for (int x = 0; x < NUM_KEYS; ++x) {

            /**
             * The number of bits to shift as specified by the key schedule
             */
            int n = keySchedule.get(x + 1);

            L = leftShift(L, n);
            R = leftShift(R, n);

            roundKeys[x] = PC2(merge(L, R));
        }

        return roundKeys;
    }

    /**
     * Expand a 32-bit sequence into a 48-bit sequence.
     *
     * @param i the 32-bit input to expand
     * @return the 48-bit expansion of i as per the specified table
     */
    private static byte[] E(byte[] i) {

        final int[] E = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };

        byte[] e = new byte[48];

        for (int x = 0; x < e.length; ++x) {

            e[x] = i[E[x] - 1];
        }

        return e;
    }

    /**
     * XOR two equal-length arrays of bytes
     *
     * @param a the first array to XOR against b
     * @param b the second array to XOR against a
     * @return the result of a XOR b
     */
    private static byte[] xOR(byte[] a, byte[] b) {

        byte[] c = new byte[a.length];

        for (int x = 0; x < c.length; ++x) {

            c[x] = (byte) (a[x] ^ b[x]);
        }

        return c;
    }

    /**
     * A 48-bit block is partitioned into 8 separate 6-bit blocks, and each
     * block is transformed into a 4-bit block using an S-box. These 8 final
     * 4-bit block are concatenated back together to form the 32-bit result.
     * This is used by each round of the cipher to create a 32-bit block out of
     * the exclusive-or result of the 48-bit round key and the expansion of the
     * right 32-bits of the original round input.
     *
     * @param i the 48-bit input
     * @return a 32-bit substitution of i as per the specified tables.
     */
    private static byte[] S(byte[] i) {

        /**
         * 8 S-boxes represented as two dimensional arrays.
         */
        final int S1[][] = {
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        };

        final int S2[][] = {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        };

        final int S3[][] = {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        };

        final int S4[][] = {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        };

        final int S5[][] = {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        };

        final int S6[][] = {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        };

        final int S7[][] = {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        };

        final int S8[][] = {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        };

        int[][][] SBoxes = {S1, S2, S3, S4, S5, S6, S7, S8};

        byte[] S = new byte[32];

        for (int x = 0, y = 0, z = 0; x < i.length; x += 6, y += 4, ++z) {

            System.arraycopy(to4BitArray(SBoxes[z][(2 * i[0 + x]) + i[5 + x]][(8 * i[1 + x]) + (4 * i[2 + x]) + (2 * i[3 + x]) + i[4 + x]]),
                    0, S, y, 4);
        }

        return S;
    }

    /**
     * Permute a 32-bit block.
     *
     * @param i the 32-bit input to permute
     * @return the 32-bit permutation of i as per the specified table
     */
    private static byte[] P(byte[] i) {

        final int[] P = {
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25,};

        byte[] p = new byte[32];

        for (int x = 0; x < i.length; ++x) {
            p[x] = i[P[x] - 1];
        }

        return p;
    }

    /**
     * Convert a positive integer to a 4-bit binary representation using an
     * array of bytes.
     *
     * @param i the positive integer to convert
     * @return the binary i represented with a byte[]
     */
    private static byte[] to4BitArray(int i) {

        final int SIZE = 4;

        /**
         * The special case i = 0 (or < 0)
         */
        if (i < 1) {
            return new byte[SIZE];
        }

        byte[] a = new byte[(int) Math.floor(Math.log(i) / Math.log(2)) + 1];

        for (int x = 0; x < a.length; ++x) {

            a[x] = (byte) ((i & (1 << ((a.length - 1) - x))) != 0 ? 1 : 0);
        }

        return addLeadingZeros(a, (SIZE - 1)
                - (int) Math.floor(Math.log(i) / Math.log(2)));
    }

    /**
     * Add a specified number of leading zeros to a binary array. Used for
     * padding.
     *
     * @param i the array to add zeroes to
     * @param z the number of zeroes to add to i
     * @return the array formed by adding z leading zeroes to i
     */
    private static byte[] addLeadingZeros(byte[] i, int z) {

        byte[] a = new byte[i.length + z];

        System.arraycopy(i, 0, a, z, i.length);

        return a;
    }

    /**
     * Swap the left and right halves of the byte array
     *
     * @param i the array to swap the left and right halves of
     * @return the array with its left and right halves swapped
     */
    private static byte[] swapLeftAndRight(byte[] i) {

        int h = (i.length / 2);
        byte[] s = new byte[i.length];

        System.arraycopy(i, h, s, 0, h);
        System.arraycopy(i, 0, s, h, h);

        return s;
    }

    /**
     * Convert a String representation of hexadecimal into an array of bytes
     * representing the binary. The result will be padded out with leading
     * zeroes if necessary. Used to turn the key String into a byte[].
     *
     * @param h the String representation of a hexadecimal value
     * @return the binary representation stored in a byte[], padded out with
     * leading zeroes if h's hexadecimal value was not 64-bits
     */
    public static byte[] hexStringTo64BitBinaryArray(String h) {

        String s = (new BigInteger(h, 16)).toString(2);
        String t = "";

        for (int x = 0; x < (64 - s.length()); ++x) {

            t += 0;
        }

        t += s;

        byte[] i = new byte[64];

        for (int x = 0; x < i.length; ++x) {

            i[x] = t.charAt(x) == '1' ? (byte) 1 : (byte) 0;
        }

        return i;
    }

    public static String intArrayToString(byte[] i) {
        String s = "";

        for (int x = 0; x < i.length; ++x) {
            s += i[x];
        }

        return s;
    }

    /**
     * Takes in a String of ASCII characters <= 8 bytes in length and returns a
     * 64-bit binary representation, padded with leading zeroes if neccessary.
     * 
     * @param input the String of ASCII characters 8 bytes or less in length
     * @return a byte[] representing the bits of input
     */
    private static byte[] binArray64(String input) {

        String bin = "";

        char[] c = input.toCharArray();

        for (int x = 0; x < c.length; ++x) {

            String a = "";

            for (int z = 0;
                    z < (8 - Integer.toBinaryString((int) c[x]).length());
                    ++z) {
                
                a += "0";
            }

            bin += (a + Integer.toBinaryString((int) c[x]));
        }

        /**
         * Pad out to 64 places with zeros.
         */
        for (int x = 0; x < (8 - input.length()); ++x) {

            bin += "00000000";
        }

        byte[] bin64 = new byte[64];

        for (int x = 0; x < bin64.length; ++x) {
            
            if (bin.charAt(x) == '1') {
                
                bin64[x] = 1;
            }
        }

        return bin64;
    }
}
