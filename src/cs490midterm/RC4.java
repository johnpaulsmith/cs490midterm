package cs490midterm;

/**
 *
 * @author: John Paul Smith CS490 Cryptography - Keene State College
 *
 * RC4.java
 *
 * RC4.java provides encryption/decryption using the RC4 algorithm. This
 * algorithm is simple and can be understood using these steps:
 *
 * 1. Create an array S of all integers 0 through 255. 
 * 2. Permute S by swapping values of indices in accordance to the key-schedule
 *    algorithm described. 
 * 3. Read in a message, one byte/character at a time, and produce a matching
 *    byte of using the resulting XOR of the ASCII value of the character and an
 *    integer value from S.
 *
 * The important concept here is that the key is only used to generate the
 * initial permutation of S, and that each byte/character of the message is
 * encrypted/decrypted separately from every other byte/character in a "stream"
 * of bytes, hence the term "stream cipher".
 *
 * Encryption and decryption are inverse functions of each other respective to
 * the same key.
 */
public class RC4 {

    /**
     * Encrypt/decrypt the message using the known 64-bit key.
     * 
     * @param message the String representation of the message 
     * @param key the 64-bit key used for both encryption and decryption
     * @return the encrypted or decrypted text
     */
    public static String rC4(String message, String key) {

        int[] S = permuteS(initialS(), key.toCharArray());

        String C = "";

        for (int i = 0, j = 0, z = 0; z < message.length(); ++z) {

            i = (i + 1) % 256;
            j = (j + S[i]) % 256;

            int t = S[i];
            S[i] = S[j];
            S[j] = t;

            int c = (S[((S[i] + S[j]) % 256)] ^ (int) message.charAt(z));

            C += (c < 16 ? "0" + Integer.toHexString(c) : Integer.toHexString(c));
        }

        return C;
    }

    /**
     * Create an array of all integers in range 0 - 255.
     * 
     * @return an array of all integers in range 0 - 255 
     */
    private static int[] initialS() {

        int[] S = new int[256];

        for (int x = 0; x < S.length; ++x) {
            
            S[x] = x;
        }

        return S;
    }

    /**
     * The initial permutation of S using the key.
     * 
     * @param S an array of all integers in range 0-255
     * @param key the 64-bit key used to permute S
     * @return S permuted using the specified algorithm
     */
    private static int[] permuteS(int[] S, char[] key) {

        int j = 0, 
                t = 0, 
                keyLength = key.length;

        for (int i = 0; i < S.length; ++i) {

            j = (j + S[i] + (int) key[i % keyLength]) % 256;

            t = S[i];
            S[i] = S[j];
            S[j] = t;
        }

        return S;
    }
}
