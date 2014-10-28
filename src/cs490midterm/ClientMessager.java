package cs490midterm;

/**
 *
 * @author: John Paul Smith CS490 Cryptography - Keene State College
 *
 * ClientMessager.java
 *
 * ClientMessager.java provides a background process which functions to send
 * messages to a secure UDP server, and listen for a response message.
 *
 * ClientMessager instances are executed in separate threads. This is because
 * the .receive() method of DatagramSocket will block until a packet is received
 * or the timeout specified limit has been exceeded. Since the interface class
 * ClientUI uses .actionPerformed() to send messages, .actionPerformed() itself
 * will not return until the methods that it has called return. Using multiple
 * thread concurrency allows the interface to still function and send messages
 * even when waiting on a response from any particular message sent to the
 * server.
 *
 * Every time the 'send' button is hit by the user, a new instance of
 * ClientMessager is created in its own thread. Each instance of ClientMessager
 * sends and receives (or times out) exactly one message, and updates the
 * interface ClientUI appropriately.
 *
 * The actual encryption/decryption of messages is done using the DES.java,
 * RC4.java, and AES.java classes. For the implementation of the algorithms,
 * please refer to those classes. ClientUI and ClientMessager are simply the
 * interface and communication mechanisms.
 */
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;

public class ClientMessager extends Thread {

    /**
     * The maximum size of the messages able to be sent at one time.
     */
    final int MAX_BUFFER_SIZE = 256;

    /**
     * This ClientMessager instance will wait this amount of time (in ms) for a
     * message from the server before closing the socket connection.
     */
    final int TIMEOUT = 30000;

    /**
     * The String constant 'KEY_STRING' is the ASCII of the 64-bit key to be
     * used in calls to both RC4.java and DES.java. The project instructions
     * require that the same key is used for everything and cannot be changed
     * dynamically. A different key is needed for AES because of the increased
     * bit-length of the minimum key.
     */
    final String KEY_STRING = "iamakey!";

    /**
     * AES requires a 128-bit key at the minimum.
     */
    final String AES_KEY_STRING = "AES 128-bit key!";

    /**
     * The Charset used by the Client and Server must be identical or
     * unpredictable behavior will result, and messages will almost certainly
     * not be able to be deciphered between Client and Server. Most JVMs running
     * on Windows 7 will have "windows-1252" (aka "Cp1252" or "Windows Latin-1")
     * as the default Charset, and Linux will generally specify "UTF-8" as the
     * default. For convenience I have hard-coded every byte[] to String
     * conversion to use the constant 'CHARSET', which has been set to "UTF-8".
     * This does not change the default encoding specified by the JVM on the
     * local machine.
     */
    final String CHARSET = StandardCharsets.UTF_8.name();

    InetSocketAddress serverSocketAddr;
    DatagramSocket clientSocket;

    ClientUI client;
    String message;

    DateFormat dateFormat;

    int encryptionMode;

    public ClientMessager(String serverIP, String serverPort, String message,
            ClientUI client, int mode) throws IOException {

        this("ClientMessager", serverIP, serverPort, message, client, mode);
    }

    public ClientMessager(String serverIP, int serverPort, String message,
            ClientUI client, int mode) throws IOException {

        this("ClientMessager", serverIP, serverPort, message, client, mode);
    }

    public ClientMessager(String name, String serverIP, String serverPort,
            String message, ClientUI client, int mode) throws IOException {

        this(name, serverIP, Integer.parseInt(serverPort), message, client,
                mode);
    }

    public ClientMessager(String name, String serverIP, int serverPort,
            String message, ClientUI client, int mode) throws IOException {

        super(name);

        serverSocketAddr = new InetSocketAddress(serverIP, serverPort);
        clientSocket = new DatagramSocket();
        clientSocket.setSoTimeout(TIMEOUT);

        this.client = client;
        this.message = message;

        dateFormat = new SimpleDateFormat("HH:mm:ss");

        encryptionMode = mode;
    }

    @Override
    public void run() {

        client.convoArea.append("["
                + dateFormat.format(Calendar.getInstance().getTime())
                + "] Message is:\n\"" + message + "\"\n");

        try {

            byte[] inputBuffer = new byte[MAX_BUFFER_SIZE];

            /**
             * A code of 0 denotes plain-text with no encryption.
             */
            if (encryptionMode == 0) {

                String cipherText = Integer.toString(encryptionMode) + message;

                clientSocket.send(new DatagramPacket(cipherText.getBytes(CHARSET),
                        cipherText.getBytes(CHARSET).length, serverSocketAddr));

                client.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Message sent to server at "
                        + serverSocketAddr.getAddress().toString() + "\n");

                DatagramPacket receivePacket = new DatagramPacket(inputBuffer,
                        inputBuffer.length);

                clientSocket.receive(receivePacket);

                /**
                 * Take the encrypted message returned from the server,
                 * decrypted it using the key, and strip any 'null' characters
                 * (ASCII value of 0) from the String
                 */
                String returnFromServer = new String(receivePacket.getData(),
                        0, receivePacket.getLength());

                client.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Received message:\n\"" + returnFromServer
                        + "\"\n returned from server at "
                        + receivePacket.getAddress() + "\n\n");
            }

            /**
             * RC4 encryption.
             */
            if (encryptionMode == 1) {

                /**
                 * Encrypt the message to send to the server.
                 */
                String cipherText = Integer.toString(encryptionMode)
                        + Utils.hexToASCII(RC4.rC4(message, KEY_STRING));

                client.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Message encrypted using RC4 is:\n\""
                        + cipherText.substring(1) + "\"\n");

                clientSocket.send(new DatagramPacket(cipherText.getBytes(CHARSET),
                        cipherText.getBytes(CHARSET).length, serverSocketAddr));

                client.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Message sent to server at "
                        + serverSocketAddr.getAddress().toString() + "\n");

                DatagramPacket receivePacket = new DatagramPacket(inputBuffer,
                        inputBuffer.length);

                clientSocket.receive(receivePacket);

                /**
                 * Take the encrypted message returned from the server,
                 * decrypted it using the key, and strip any 'null' characters
                 * (ASCII value of 0) from the String.
                 */
                String returnFromServer = new String(receivePacket.getData(), 0,
                        receivePacket.getLength(), CHARSET);

                String decryptedMessage
                        = Utils.hexToASCII(RC4.rC4(returnFromServer, KEY_STRING));

                client.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Received message:\n\"" + decryptedMessage
                        + "\"\n returned from server at "
                        + receivePacket.getAddress() + "\n\n");
            }

            /**
             * DES encryption.
             */
            if (encryptionMode == 2) {

                /**
                 * Encrypt the message to send to the server.
                 */
                String cipherText = Integer.toString(encryptionMode)
                        + DES.encryptMessage(message,
                                Utils.ASCIIToHexString(KEY_STRING));

                client.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Message encrypted using DES is:\n\""
                        + cipherText.substring(1) + "\"\n");

                clientSocket.send(new DatagramPacket(cipherText.getBytes(CHARSET),
                        cipherText.getBytes(CHARSET).length, serverSocketAddr));

                client.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Message sent to server at "
                        + serverSocketAddr.getAddress().toString() + "\n");

                DatagramPacket receivePacket = new DatagramPacket(inputBuffer,
                        inputBuffer.length);

                clientSocket.receive(receivePacket);

                /**
                 * Take the encrypted message returned from the server,
                 * decrypted it using the key, and strip any 'null' characters
                 * (ASCII value of 0) from the String.
                 */
                String returnFromServer = new String(receivePacket.getData(), 0,
                        receivePacket.getLength(), CHARSET);

                String decryptedMessage
                        = Utils.stripNulls(DES.decryptMessage(returnFromServer,
                                        Utils.ASCIIToHexString(KEY_STRING)));

                client.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Received message:\n\"" + decryptedMessage
                        + "\"\n returned from server at "
                        + receivePacket.getAddress() + "\n\n");
            }

            /**
             * AES encryption.
             */
            if (encryptionMode == 3) {

                /**
                 * Encrypt the message to send to the server.
                 */
                String cipherText = Integer.toString(encryptionMode)
                        + AES.encrypt(message, AES_KEY_STRING);

                client.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Message encrypted using AES is:\n\""
                        + cipherText.substring(1) + "\"\n");

                clientSocket.send(new DatagramPacket(cipherText.getBytes(CHARSET),
                        cipherText.getBytes(CHARSET).length, serverSocketAddr));

                client.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Message sent to server at "
                        + serverSocketAddr.getAddress().toString() + "\n");

                DatagramPacket receivePacket = new DatagramPacket(inputBuffer,
                        inputBuffer.length);

                clientSocket.receive(receivePacket);

                String returnFromServer = new String(receivePacket.getData(), 0,
                        receivePacket.getLength(), CHARSET);

                String decryptedMessage = AES.decrypt(returnFromServer,
                        AES_KEY_STRING);

                client.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Received message:\n\"" + decryptedMessage
                        + "\"\n returned from server at "
                        + receivePacket.getAddress() + "\n\n");
            }

        } catch (java.net.SocketTimeoutException t) {

            client.convoArea.append("["
                    + dateFormat.format(Calendar.getInstance().getTime())
                    + "] Response from server at "
                    + serverSocketAddr.getAddress().toString()
                    + " not received within " + TIMEOUT
                    + "ms, closing socket connection\n\n");

        } catch (IOException ex) {

            client.convoArea.append(ex.getMessage() + "\n");
        } catch (Exception ex) {

            /**
             * Catch all other exceptions. This will catch the multiple
             * exceptions associated with the javax.crypto classes.
             */
            client.convoArea.append("["
                    + dateFormat.format(Calendar.getInstance().getTime())
                    + "] Something went wrong:\n"
                    + ex.getMessage());
        }

        clientSocket.close();
    }
}
