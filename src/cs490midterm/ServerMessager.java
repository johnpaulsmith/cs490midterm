package cs490midterm;

/**
 *
 * @author: John Paul Smith CS490 Cryptography - Keene State College
 *
 * ServerMessager.java
 *
 * ServerMessager provides a background process which functions to receive, and
 * in response return, messages sent to a secure UDP server from clients. All
 * network communications are done from within this class. This simple server is
 * comprised of two components: an instance of ServerUI and an instance of
 * ServerMessager. Data is transmitted from clients to the server and received
 * within ServerMessager. ServerMessager decrypts (if the message was encrypted)
 * the messages sent to the server, updates the ServerUI to display the
 * messages, and sends the appropriate messages back to the clients.
 *
 * The actual encryption/decryption of messages is done using the DES.java,
 * RC4.java, and AES.java classes. For the implementation of the algorithms,
 * please refer to those classes. ServerUI and ServerMessager are simply the
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

public class ServerMessager extends Thread {

    /**
     * The maximum size of the messages able to be sent at one time.
     */
    final int MAX_BUFFER_SIZE = 256;

    /**
     * The ServerMessager instance will wait this amount of time (in ms) for a
     * message from the client before closing the socket connection.
     */
    final int TIMEOUT = 3000000;

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

    DatagramSocket serverSocket;
    InetSocketAddress serverSocketAddr;

    DateFormat dateFormat;

    ServerUI server;

    public ServerMessager(String serverIP, String serverPort, ServerUI server)
            throws IOException {

        this("Server Messager", serverIP, serverPort, server);
    }

    public ServerMessager(String serverIP, int serverPort, ServerUI server)
            throws IOException {

        this("Server Messager", serverIP, serverPort, server);
    }

    public ServerMessager(String name, String serverIP, String serverPort,
            ServerUI server) throws IOException {

        this(name, serverIP, Integer.parseInt(serverPort), server);
    }

    public ServerMessager(String name, String serverIP, int serverPort,
            ServerUI server) throws IOException {

        super(name);

        serverSocketAddr = new InetSocketAddress(serverIP, serverPort);
        serverSocket = new DatagramSocket(serverSocketAddr);
        serverSocket.setSoTimeout(TIMEOUT);

        this.server = server;

        dateFormat = new SimpleDateFormat("HH:mm:ss");
    }

    @Override
    public void run() {
        server.convoArea.append("["
                + dateFormat.format(Calendar.getInstance().getTime())
                + "] Server messager service started on "
                + serverSocketAddr.getAddress().toString()
                + "\nListening for message from client...\n\n");

        while (true) {

            byte[] inputBuffer = new byte[MAX_BUFFER_SIZE];

            DatagramPacket receivePacket = new DatagramPacket(inputBuffer,
                    inputBuffer.length);

            try {

                serverSocket.receive(receivePacket);

                String messageReceived = new String(receivePacket.getData(), 0,
                        receivePacket.getLength(), CHARSET);

                int encryptionMode
                        = Integer.parseInt(messageReceived.substring(0, 1));

                /**
                 * Remove the first character, which is the encryption mode code.
                 */
                messageReceived = messageReceived.substring(1);

                /**
                 * A code of 0 denotes plain-text with no encryption.
                 */
                if (encryptionMode == 0) {

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Received plainttext message:\n\""
                            + messageReceived + "\"\nfrom client at "
                            + receivePacket.getAddress() + "\n");

                    InetSocketAddress clientAddr
                            = new InetSocketAddress(receivePacket.getAddress(),
                                    receivePacket.getPort());

                    /**
                     * Return an uppercase version of the message to the client.
                     */
                    String returnToClient = messageReceived.toUpperCase();

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Sending message \n\""
                            + returnToClient + "\" back to client\n");

                    serverSocket.send(new DatagramPacket(returnToClient.getBytes(),
                            returnToClient.getBytes().length, clientAddr));

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Message sent to client at "
                            + clientAddr.getAddress().toString() + "\n\n");
                }

                /**
                 * Code 1 denotes RC4 encryption used by client.
                 */
                if (encryptionMode == 1) {

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Received encrypted message:\n\""
                            + messageReceived + "\"\nfrom client at "
                            + receivePacket.getAddress() + "\n");

                    /**
                     * Decrypt the message received from a client, removing any
                     * null (ASCII value of 0) characters from the String.
                     */
                    String decryptedMessage
                            = Utils.hexToASCII(RC4.rC4(messageReceived,
                                            KEY_STRING));

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Message was decrypted using RC4 algorithm:\n\""
                            + decryptedMessage + "\"\n");

                    InetSocketAddress clientAddr
                            = new InetSocketAddress(receivePacket.getAddress(),
                                    receivePacket.getPort());

                    /**
                     * Return an uppercase version of the message to the client.
                     */
                    String returnToClient = decryptedMessage.toUpperCase();

                    String encryptedMessage
                            = Utils.hexToASCII(RC4.rC4(returnToClient,
                                    KEY_STRING));

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Sending encrypted message \n\""
                            + encryptedMessage + "\"\n back to client\n");

                    serverSocket.send(new DatagramPacket(encryptedMessage.getBytes(CHARSET),
                            encryptedMessage.getBytes(CHARSET).length, clientAddr));

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Message sent to client at "
                            + clientAddr.getAddress().toString() + "\n\n");
                }

                /**
                 * Code 2 denotes DES encryption used by client.
                 */
                if (encryptionMode == 2) {

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Received encrypted message:\n\""
                            + messageReceived + "\"\nfrom client at "
                            + receivePacket.getAddress() + "\n");

                    /**
                     * Decrypt the message received from a client, removing any
                     * null (ASCII value of 0) characters from the String.
                     */
                    String decryptedMessage
                            = Utils.stripNulls(DES.decryptMessage(messageReceived,
                                            Utils.ASCIIToHexString(KEY_STRING)));

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Message was decrypted using DES algorithm:\n\""
                            + decryptedMessage + "\"\n");

                    InetSocketAddress clientAddr
                            = new InetSocketAddress(receivePacket.getAddress(),
                                    receivePacket.getPort());

                    /**
                     * Return an uppercase version of the message to the client.
                     */
                    String returnToClient = decryptedMessage.toUpperCase();

                    String encryptedMessage
                            = DES.encryptMessage(returnToClient,
                                    Utils.ASCIIToHexString(KEY_STRING));

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Sending encrypted message \n\""
                            + encryptedMessage + "\"\n back to client\n");

                    serverSocket.send(new DatagramPacket(encryptedMessage.getBytes(CHARSET),
                            encryptedMessage.getBytes(CHARSET).length, clientAddr));

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Message sent to client at "
                            + clientAddr.getAddress().toString() + "\n\n");
                }

                /**
                 * Code 3 denotes AES encryption used by client.
                 */
                if (encryptionMode == 3) {

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Received encrypted message:\n\""
                            + messageReceived + "\"\nfrom client at "
                            + receivePacket.getAddress() + "\n");

                    String decryptedMessage = AES.decrypt(messageReceived,
                            AES_KEY_STRING);

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Message was decrypted using AES algorithm:\n\""
                            + decryptedMessage + "\"\n");

                    InetSocketAddress clientAddr
                            = new InetSocketAddress(receivePacket.getAddress(),
                                    receivePacket.getPort());

                    /**
                     * Return an uppercase version of the message to the client.
                     */
                    String returnToClient = decryptedMessage.toUpperCase();

                    String encryptedMessage = AES.encrypt(returnToClient,
                            AES_KEY_STRING);

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Sending encrypted message \n\""
                            + encryptedMessage + "\"\n back to client\n");

                    serverSocket.send(new DatagramPacket(encryptedMessage.getBytes(CHARSET),
                            encryptedMessage.getBytes(CHARSET).length, clientAddr));

                    server.convoArea.append("["
                            + dateFormat.format(Calendar.getInstance().getTime())
                            + "] Message sent to client at "
                            + clientAddr.getAddress().toString() + "\n\n");
                }

            } catch (java.net.SocketTimeoutException t) {

                /**
                 * This exception will be thrown by the currently executing
                 * 'serverSocket.receive(receivePacket)' method. This method
                 * will block until a packet is received or the timeout limit
                 * specified is reached. If the timeout is exceeded, a new
                 * SocketTimeoutException will be thrown by .receive() and
                 * caught here. The DatagramSocket 'serverSocket' will be closed
                 * and the thread will terminate.
                 */
                server.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Server messager service timed out after waiting "
                        + TIMEOUT
                        + " ms for client message, closing socket connection\n");

                server.isRunning = false;

                serverSocket.close();

                break;

            } catch (IOException ex) {
                server.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] An I/O error occurred -- restart server:\n"
                        + ex.getMessage());
            } catch (Exception ex) {
                /**
                 * Catch all other exceptions, this will catch the multiple
                 * exceptions associated with the javax.crypto classes.
                 */
                server.convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] Something went wrong:\n"
                        + ex.getMessage());
            }
        }
    }
}
