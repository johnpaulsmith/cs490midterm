package cs490midterm;

/**
 *
 * @author: John Paul Smith CS490 Cryptography - Keene State College
 *
 * Utils.java
 *
 * Utils.java contains several methods that I felt were utilities that should be
 * independent of any of the other classes.
 */
import java.math.BigInteger;

public class Utils {

    /**
     * Convert a String of ASCII characters to a String representation of the
     * hexadecimal values of each ASCII character.
     *
     * @param ascii the String of ASCII characters
     * @return the hexadecimal values of all ASCII characters of ascii,
     * represented by a String
     */
    public static String ASCIIToHexString(String ascii) {

        String hex = "";

        for (int x = 0; x < ascii.length(); ++x) {

            hex += Integer.toString((int) ascii.charAt(x), 16);
        }

        return hex;
    }

    /**
     * Remove any null characters (ASCII value of 0) from a String. The method
     * by which java.net.DatagramPacket stores data is with a fixed-length array
     * of bytes. Unused indices of this byte buffer are parsed into Strings as
     * null characters.
     *
     * @param s a String containing null characters that need to be removed
     * @return the String containing all the non-null characters of S
     */
    public static String stripNulls(String s) {

        String t = "";

        for (int x = 0; x < s.length(); ++x) {
            if ((int) s.charAt(x) != 0) {
                t += s.charAt(x);
            }
        }

        return t;
    }

    /**
     * Return an ASCII representation of an arbitrarily sized hex String
     * 
     * @param i the hexadecimal String
     * @return the String created when all bytes represented in hexadecimal in S
     *         are converted into ASCII characters
     */
    public static String hexToASCII(String i) {

        if (i.length() % 2 != 0) {
            i = "0" + i;
        }

        String output = "";

        for (int x = 0; x < i.length(); x += 2) {
            output += Character.toString((char) (new BigInteger(Character.toString(i.charAt(x))
                    + Character.toString(i.charAt(x + 1)), 16).intValue()));
        }

        return output;
    }
}
