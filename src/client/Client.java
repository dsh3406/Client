/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package client;

/**
 *
 * @author hamzaikine, suhyundo
 */
import com.sun.xml.internal.messaging.saaj.packaging.mime.util.BASE64DecoderStream;
import com.sun.xml.internal.messaging.saaj.packaging.mime.util.BASE64EncoderStream;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SignatureException;
import java.util.Formatter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Client {

    private BufferedReader in;
    private PrintWriter out;
    private JFrame frame = new JFrame("Capitalize Client");
    private JTextField dataField = new JTextField(40);
    private JTextArea messageArea = new JTextArea(8, 60);
    private static final String HMAC_SHA1 = "HmacSHA1";

    public Client() {

        // Layout GUI
        messageArea.setEditable(false);
        frame.getContentPane().add(dataField, "North");
        frame.getContentPane().add(new JScrollPane(messageArea), "Center");

        // Add Listeners
        dataField.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {

                try {

                    // encrytp message
                    ecipher = Cipher.getInstance("DES");
                    ecipher.init(Cipher.ENCRYPT_MODE, key);

                    String hmac = calculateHMAC(dataField.getText(), "key");
                    String encrypted = encrypt(hmac + dataField.getText());
                    System.out.println("Encrypted message: " + encrypted);

                    // System.out.println(encrypted);
                    // sending the encrypted message with hmac
                    out.println(encrypted);

                    String response = null;
                    String decrypted = null;
                    String message = null;
                    try {

                        // we receive an encrypted message from the server
                        dcipher = Cipher.getInstance("DES");
                        dcipher.init(Cipher.DECRYPT_MODE, key);

                        response = in.readLine();
                        
                        
                         if (response == null || response.equals("")) {
                            System.exit(0);
                        }
                        
                        decrypted = decrypt(response);

                        String hmacFromServer = decrypted.substring(0, 40);
                        message = decrypted.substring(40, decrypted.length());

                        String check = calculateHMAC(message, "key");

                        if (check.equals(hmac)) {
                            System.out.println("Hmac:" + hmac + " is the same. The message has not changed in transit from server.\n");
                        } else {
                            System.out.println("not the same.");
                        }

                        
                        
                       
                    } catch (IOException ex) {
                        response = "Error: " + ex;
                    } catch (InvalidKeyException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    }
                        messageArea.append(message + " received from server has not changed.\n");
                        dataField.selectAll();
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchPaddingException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeyException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SignatureException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
    }

    public void connectToServer() throws IOException {

        // Get the server address from a dialog box.
        String serverAddress = JOptionPane.showInputDialog(
                frame,
                "Enter IP Address of the Server:",
                "Welcome to the Capitalization Program",
                JOptionPane.QUESTION_MESSAGE);

        // Make connection and initialize streams
        Socket socket = new Socket(serverAddress, 9898);
        in = new BufferedReader(
                new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);

        // Consume the initial welcoming messages from the server
        for (int i = 0; i < 3; i++) {
            messageArea.append(in.readLine() + "\n");
        }
    }

    /**
     * Runs the client application.
     */
    private static Cipher ecipher;
    private static Cipher dcipher;

    private static SecretKey key;

    public static void main(String[] args) throws Exception {

        try {
            // generate secret key using DES algorithm
            // key = KeyGenerator.getInstance("DES").generateKey();

            // System.out.println("keep it secret: " + key.toString());
//            ecipher = Cipher.getInstance("DES");
//            dcipher = Cipher.getInstance("DES");
//            dcipher.init(Cipher.DECRYPT_MODE, key);
//
//            String encrypted = encrypt("This is a classified message!");
//
//            String decrypted = decrypt(encrypted);
//
//                System.out.println("Decrypted: " + decrypted);
            String filepath = "key.txt";
//            FileOutputStream fileOut = new FileOutputStream(filepath);
//            ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);
//            objectOut.writeObject(key);
//            objectOut.close();

//  read from file
            FileInputStream fileIn = new FileInputStream(filepath);
            ObjectInputStream objectIn = new ObjectInputStream(fileIn);
            key = (SecretKey) objectIn.readObject();
            System.out.println(key.toString());

//             // initialize the ciphers with the given key
//            ecipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (Exception e) {
            System.out.println("file not found" + e.getMessage());
            return;
        }

        Client client = new Client();
        client.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        client.frame.pack();
        client.frame.setVisible(true);
        client.connectToServer();
    }

    public static String encrypt(String str) {

        try {

            // encode the string into a sequence of bytes using the named charset
            // storing the result into a new byte array. 
            byte[] utf8 = str.getBytes("UTF8");

            byte[] enc = ecipher.doFinal(utf8);

// encode to base64
            enc = BASE64EncoderStream.encode(enc);

            return new String(enc);

        } catch (Exception e) {

            e.printStackTrace();

        }

        return null;

    }

    public static String decrypt(String str) {

        try {

            // decode with base64 to get bytes
            byte[] dec = BASE64DecoderStream.decode(str.getBytes());

            byte[] utf8 = dcipher.doFinal(dec);

// create new string based on the specified charset
            return new String(utf8, "UTF8");

        } catch (Exception e) {

            e.printStackTrace();

        }

        return null;

    }

    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    public static String calculateHMAC(String data, String key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), HMAC_SHA1);
        Mac mac = Mac.getInstance(HMAC_SHA1);
        mac.init(secretKeySpec);
        return toHexString(mac.doFinal(data.getBytes()));
    }
}
