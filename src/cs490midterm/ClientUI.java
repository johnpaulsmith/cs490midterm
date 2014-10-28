package cs490midterm;

/**
 *
 * @author: John Paul Smith CS490 Cryptography - Keene State College
 *
 * ClientUI.java
 *
 * ClientUI.java provides an interface for the construction of messages,
 * encryption method selection, and sending/receiving of messages from a client
 * to a secure UPD server.
 *
 * The user may select the preferred method of encryption (or none at all) and
 * send messages to a secure UDP server. If a response is received, the response
 * message will be decrypted (if necessary) and displayed. The response from the
 * server should be an all-uppercase match of the message sent by the client.
 *
 * The actual encryption/decryption of messages is done using the DES.java,
 * RC4.java, and AES.java classes. For the implementation of the algorithms,
 * please refer to those classes. ClientUI and ClientMessager are simply the
 * interface and communication mechanisms.
 */
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import javax.swing.*;

public class ClientUI extends JPanel implements ActionListener {

    final String SERVER_IP = "74.78.99.204";
    final String SERVER_PORT = "4437";

    JPanel inputPanel, buttonPanel, topPanel, leftSpacer, rightSpacer,
            centerContentPanel;
    JTextField messageInputField;
    JTextArea convoArea;
    JScrollPane messagePane;
    JButton sendButton, offButton, RC4Button, DESButton, AESButton, clearButton;
    Color bgColor, panelColor, buttonDefaultColor, buttonSelectedColor;

    DateFormat dateFormat;

    int encryptionMode;

    public ClientUI() {

        super(new BorderLayout(20, 0));

        encryptionMode = 0;

        dateFormat = new SimpleDateFormat("HH:mm:ss");

        panelColor = new Color(245, 245, 245);
        bgColor = new Color(220, 220, 220);
        buttonDefaultColor = new Color(238, 238, 238);
        buttonSelectedColor = Color.red;

        sendButton = new JButton("Send");
        sendButton.addActionListener(this);

        offButton = new JButton("Off");
        offButton.addActionListener(this);

        RC4Button = new JButton("RC4");
        RC4Button.addActionListener(this);

        DESButton = new JButton("DES");
        DESButton.addActionListener(this);

        AESButton = new JButton("AES");
        AESButton.addActionListener(this);

        clearButton = new JButton("Clear messages");
        clearButton.addActionListener(this);

        messageInputField = new JTextField(84);
        messageInputField.addActionListener(this);

        convoArea = new JTextArea();
        convoArea.setBackground(panelColor);
        convoArea.setEditable(false);

        messagePane = new JScrollPane(convoArea);
        messagePane.setPreferredSize(new Dimension(768, 512));

        inputPanel = new JPanel();
        inputPanel.setBackground(bgColor);
        inputPanel.add(messageInputField);
        inputPanel.add(sendButton);

        buttonPanel = new JPanel();
        buttonPanel.setBackground(panelColor);
        buttonPanel.setPreferredSize(new Dimension(192, 100));
        buttonPanel.setBorder(BorderFactory.createBevelBorder(1));
        buttonPanel.add(RC4Button);
        buttonPanel.add(DESButton);
        buttonPanel.add(AESButton);
        buttonPanel.add(offButton);
        buttonPanel.add(clearButton);

        topPanel = new JPanel();
        topPanel.setBackground(bgColor);

        centerContentPanel = new JPanel(new BorderLayout(20, 0));
        centerContentPanel.setBackground(bgColor);
        centerContentPanel.add(messagePane, BorderLayout.WEST);
        centerContentPanel.add(buttonPanel, BorderLayout.EAST);

        leftSpacer = new JPanel();
        leftSpacer.setBackground(bgColor);
        leftSpacer.setPreferredSize(new Dimension(0, 0));

        rightSpacer = new JPanel();
        rightSpacer.setBackground(bgColor);
        rightSpacer.setPreferredSize(new Dimension(0, 0));

        setBackground(bgColor);
        add(leftSpacer, BorderLayout.WEST);
        add(rightSpacer, BorderLayout.EAST);
        add(inputPanel, BorderLayout.SOUTH);
        add(topPanel, BorderLayout.NORTH);
        add(centerContentPanel, BorderLayout.CENTER);
    }

    @Override
    public void actionPerformed(ActionEvent ae) {

        /**
         * If the "Off" button is pressed, deactivate encryption and send only
         * plainttext messages. Set the encryptionMode value to 0.
         */
        if (ae.getSource() == offButton) {

            RC4Button.setBackground(buttonDefaultColor);
            DESButton.setBackground(buttonDefaultColor);
            AESButton.setBackground(buttonDefaultColor);

            encryptionMode = 0;

            convoArea.append("["
                    + dateFormat.format(Calendar.getInstance().getTime())
                    + "] Encryption deactivated\n\n");
        }

        /**
         * If the "RC4" button is pressed, set the encryptionMode value to 1.
         * All messages sent will be encrypted using the RC4 implementation
         * found in RC4.java
         */
        if (ae.getSource() == RC4Button) {

            RC4Button.setBackground(buttonSelectedColor);
            DESButton.setBackground(buttonDefaultColor);
            AESButton.setBackground(buttonDefaultColor);

            encryptionMode = 1;

            convoArea.append("["
                    + dateFormat.format(Calendar.getInstance().getTime())
                    + "] RC4 encryption enabled\n\n");
        }

        /**
         * If the "DES" button is pressed, set the encryptionMode value to 2.
         * All messages sent will be encrypted using the DES implementation
         * found in DES.java.
         */
        if (ae.getSource() == DESButton) {

            RC4Button.setBackground(buttonDefaultColor);
            DESButton.setBackground(buttonSelectedColor);
            AESButton.setBackground(buttonDefaultColor);

            encryptionMode = 2;

            convoArea.append("["
                    + dateFormat.format(Calendar.getInstance().getTime())
                    + "] DES encryption enabled\n\n");
        }

        /**
         * If the "AES" button is pressed, set the encryptionMode value to 3.
         * All messages sent will be encrypted using the AES implementation
         * found in AES.java.
         */
        if (ae.getSource() == AESButton) {

            RC4Button.setBackground(buttonDefaultColor);
            DESButton.setBackground(buttonDefaultColor);
            AESButton.setBackground(Color.red);

            encryptionMode = 3;

            convoArea.append("["
                    + dateFormat.format(Calendar.getInstance().getTime())
                    + "] AES encryption enabled\n\n");
        }

        /**
         * If the "Send" button is pressed, validate the input (must be at least
         * one character) and construct a new ClientMessager instance in a
         * separate thread. This ClientMessager will send the message to the
         * server and receive a response if a response is sent back.
         */
        if (ae.getSource() == messageInputField
                || ae.getSource() == sendButton) {

            String input = messageInputField.getText();

            if (input.length() > 0) {

                try {

                    ClientMessager m = new ClientMessager(SERVER_IP,
                            SERVER_PORT, input, this, encryptionMode);
                    
                    m.start();

                } catch (IOException | IllegalArgumentException ex) {
                    
                    convoArea.append("An error occured trying to bind a socket"
                            + "connection to IP address " + SERVER_IP + " and "
                            + "port " + SERVER_PORT + "\n" + ex.getMessage());
                }
            }

            messageInputField.setText("");
        }

        if (ae.getSource() == clearButton) {
            
            convoArea.setText("");
        }
    }

    public static void main(String[] args) {

        ClientUI clientPanel = new ClientUI();

        JFrame frame = new JFrame("Secure UDP Client");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setResizable(false);
        frame.getContentPane().add(clientPanel, BorderLayout.CENTER);
        frame.pack();
        frame.setVisible(true);
    }
}
