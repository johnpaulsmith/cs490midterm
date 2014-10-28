package cs490midterm;

/**
 *
 * @author: John Paul Smith CS490 Cryptography - Keene State College
 *
 * ServerUI.java
 *
 * ServerUI.java provides an interface for the display of messages sent to a
 * secure UPD server. This simple server is comprised of two components: an
 * instance of ServerUI and an instance of ServerMessager. Data is transmitted
 * from clients to the server and received within ServerMessager. ServerMessager
 * decrypts (if the message was encrypted) the messages sent to the server,
 * updates the ServerUI to display the messages, and sends the appropriate
 * messages back to the clients.
 *
 * The actual encryption/decryption of messages is done using the DES.java,
 * RC4.java, and AES.java classes. For the implementation of the algorithms,
 * please refer to those classes. ServerUI and ServerMessager are simply the
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

public class ServerUI extends JPanel implements ActionListener {

    final static String SERVER_IP = "74.78.99.204";
    final static String SERVER_PORT = "4437";

    JPanel inputPanel, buttonPanel, topPanel, leftSpacer, rightSpacer,
            centerContentPanel;
    JTextArea convoArea;
    JScrollPane messagePane;
    JButton clearButton, startButton;
    Color bgColor, panelColor;
    Dimension buttonSize = new Dimension(127, 26);
    DateFormat dateFormat;
    boolean isRunning;

    public ServerUI() {

        super(new BorderLayout(20, 0));

        isRunning = false;

        dateFormat = new SimpleDateFormat("HH:mm:ss");

        panelColor = new Color(245, 245, 245);
        bgColor = new Color(220, 220, 220);

        clearButton = new JButton("Clear messages");
        clearButton.addActionListener(this);
        clearButton.setPreferredSize(buttonSize);

        startButton = new JButton("Start server");
        startButton.addActionListener(this);
        startButton.setPreferredSize(buttonSize);

        convoArea = new JTextArea();
        convoArea.setBackground(panelColor);
        convoArea.setEditable(false);

        messagePane = new JScrollPane(convoArea);
        messagePane.setPreferredSize(new Dimension(768, 512));

        inputPanel = new JPanel();
        inputPanel.setBackground(bgColor);

        buttonPanel = new JPanel();
        buttonPanel.setBackground(panelColor);
        buttonPanel.setPreferredSize(new Dimension(192, 100));
        buttonPanel.setBorder(BorderFactory.createBevelBorder(1));
        buttonPanel.add(clearButton);
        buttonPanel.add(startButton);

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

    public void addListeners() {

    }

    @Override
    public void actionPerformed(ActionEvent ae) {

        if (ae.getSource() == clearButton) {
            convoArea.setText("");
        }

        if (ae.getSource() == startButton) {

            if (isRunning) {
                convoArea.append("["
                        + dateFormat.format(Calendar.getInstance().getTime())
                        + "] The server is already running\n\n");
            } else {
                startServices();
            }
        }
    }

    /**
     * Start a new instance of ServerMessager using the IP address and port
     * numbers provided. The ServerMessager will run in its own thread until it
     * times out.
     */
    public void startServices() {

        try {
            new ServerMessager(SERVER_IP, SERVER_PORT, this).start();
            isRunning = true;

        } catch (IOException | IllegalArgumentException ex) {

            convoArea.append("An error occured trying to bind a socket "
                    + "connection to IP address " + SERVER_IP + " and port "
                    + SERVER_PORT + "\n" + ex.getMessage());
        }
    }

    public static void main(String[] args) {

        ServerUI server = new ServerUI();

        JFrame frame = new JFrame("Secure UDP Server");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setResizable(false);
        frame.getContentPane().add(server, BorderLayout.CENTER);
        frame.pack();
        frame.setVisible(true);

        server.startServices();
    }
}
