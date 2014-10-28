package cs490midterm;

/**
 *
 * @author: John Paul Smith CS490 Cryptography - Keene State College
 *
 * AES.java
 *
 * A basic interface for encrypting/decrypting messages using AES.
 *
 * The implementation for AES is provided by the javax.crypto.Cipher and
 * javax.crypto.spec.SecretKeySpec classes.
 *
 * NOTE: the use of sun.misc.BASE64Encoder and sun.misc.BASE64Decoder will cause
 * the Java compiler to throw a warning fit (but still compile). Oracle has
 * denounced use of classes within third-party packages. I used these because I
 * needed a quick and dirty base-64 implementation. This is not good programming
 * practice, and I would never advocate such usage in production code. This is
 * is just for fun and a few extra points on this project.
 */
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class AES {

    public static String encrypt(String message, String keyString)
            throws Exception {

        Cipher cipherAES = Cipher.getInstance("AES");

        cipherAES.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(keyString.getBytes(), "AES"));

        return new BASE64Encoder().encode(cipherAES.doFinal(message.getBytes()));
    }

    public static String decrypt(String message, String keyString)
            throws Exception {

        Cipher cipherAES = Cipher.getInstance("AES");

        cipherAES.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(keyString.getBytes(), "AES"));

        return new String(cipherAES.doFinal(new BASE64Decoder().decodeBuffer(message)));
    }
}
