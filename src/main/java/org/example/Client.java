package org.example;

import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.rmi.Naming;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import javax.crypto.*;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client {
    private static LoadBalancerInterface loadBalancer;
    private JFrame frame = new JFrame("Chat Client ");
    private JPanel panelName = new JPanel();
    private JLabel labelName = new JLabel("Enter your name: ");
    private JButton buttonName = new JButton("Enter");
    private JTextField textFieldName = new JTextField(20);
    private JPanel panelBump = new JPanel();
    private JButton buttonBump = new JButton();
    private JPanel panelText = new JPanel();
    private JTextArea labelText = new JTextArea();
    private JButton buttonText = new JButton("Send");
    private JTextField textFieldText = new JTextField(20);
    private CardLayout cardLayout = new CardLayout();
    private JPanel cardPanel = new JPanel(cardLayout);
    private String name = "";
    private Thread printer;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private int receiveCell;
    private int sendCell;
    private static final String CHARACTERS = "abcdefghijklmnopqrstuvwxyz";
    private final Random random = new Random();
    private String sendTag;
    private String receiveTag;
    private PublicKey othersPublicKey;
    private SecretKey secretKey = null;
    private Cipher cipher;
    private byte[] generatedSecret;
    private static final Logger LOGGER = Logger.getLogger(Client.class.getName());
    private static final int TAG_LENGTH = 10;
    private AtomicInteger bumpFileIsGenerated = new AtomicInteger(0);
    private int sendServer;

    public Client() {
        String host = "localhost";
        generateKeys();

        try {
            loadBalancer = (LoadBalancerInterface) Naming.lookup("rmi://"+host+"/LoadBalancer");
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            initialiseJframe();
            initialiseMessagePrinter();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in constructor", e);
        }
    }

    private void initialiseJframe() {
        frame.setSize(350, 300);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        initialiseNamePanel();
        initialiseBumpPanel();
        initialiseTextPanel();

        cardPanel.add(panelName, "panelName");
        cardPanel.add(panelBump, "panelBump");
        cardPanel.add(panelText, "panelText");

        frame.getContentPane().add(cardPanel);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private void initialiseNamePanel () {
        buttonName.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                name = textFieldName.getText();
                textFieldName.setText("");
                frame.setTitle("Chat client "+name);
                cardLayout.show(cardPanel, "panelBump");
            }
        });
        textFieldName.setText("");
        panelName.add(labelName);
        panelName.add(textFieldName);
        panelName.add(buttonName);
    }

    private void initialiseBumpPanel () {
        buttonBump.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    if (bumpFileIsGenerated.get() == 0) {
                        bumpFileIsGenerated.set(1);
                        generateBumpFile();
                        Thread bumpFinder = new Thread(()-> {
                            getBumpFile(getBumpName());
                            cardLayout.show(cardPanel, "panelText");
                            printer.start();
                        });
                        bumpFinder.start();
                    }
                } catch (Exception ex) {
                    LOGGER.log(Level.SEVERE, "Error bumping", e);
                }
            }
        });
        buttonBump.setText("BUMP");
        panelBump.add(buttonBump);
    }

    private void initialiseTextPanel () {
        labelText.setLocation(0,0);
        labelText.setPreferredSize(new Dimension(300, 220));
        labelText.setEditable(false);
        labelText.setLineWrap(true);
        labelText.setWrapStyleWord(true);

        textFieldText.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    buttonText.doClick();
                }
            }
        });

        buttonText.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String message = textFieldText.getText();
                if (!message.isEmpty()) send(message);
                textFieldText.setText("");
            }
        });
        panelText.add(labelText);
        panelText.add(textFieldText);
        panelText.add(buttonText);
    }

    private void send(String message) {
        if (!message.isEmpty()){
            int nextCell = generateRandomIndex();
            String nextTag = generateTag(TAG_LENGTH);
            String formattedMessage = name+": "+message+"'"+nextCell+"'"+nextTag;
            String encryptedMessage = encrypt(formattedMessage);

            try {
                loadBalancer.postMessage(sendCell, getHash(sendTag), encryptedMessage);
                sendTag = nextTag;
                sendCell = nextCell;
                deriveKey();
                if (labelText.getText().isEmpty()) labelText.setText(name +": "+message);
                else labelText.setText(labelText.getText() + "\n" + name +": "+message);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Error sending message", e);
            }
        }
    }

    private void read() {
        try {
            List<String> messages = loadBalancer.getMessage(receiveCell, receiveTag);
            if (!messages.isEmpty()) {
                for (String message: messages) {
                    message = decrypt(message);

                    if (message != null && message.split("'").length == 3) {
                        String[] parts = message.split("'");
                        message = parts[0];
                        if (labelText.getText().isEmpty()) labelText.setText(message);
                        else labelText.setText(labelText.getText() + "\n" + message);

                        receiveCell = Integer.parseInt(parts[1]);
                        receiveTag = parts[2];
                        deriveKey();
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in read()", e);
        }
    }

    private void initialiseMessagePrinter() {
        printer = new Thread(() -> {
            try {
                while (true) {
                    read();
                    Thread.sleep(800);
                }
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Error reading messages", e);
            }
        });
    }

    private void deriveKey() {
        try {
            byte[] input;
            byte[] derivedKey = new byte[16];

            if (secretKey == null) {
                input = Arrays.copyOf(privateKey.getEncoded(), privateKey.getEncoded().length + othersPublicKey.getEncoded().length);
                System.arraycopy(othersPublicKey.getEncoded(), 0, input, privateKey.getEncoded().length, othersPublicKey.getEncoded().length);
                KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
                keyAgreement.init(privateKey);
                keyAgreement.doPhase(othersPublicKey, true);
                generatedSecret = keyAgreement.generateSecret();
                System.arraycopy(generatedSecret, 0, derivedKey, 0, 16);
            } else {
                SecretKeySpec secretKeySpec = new SecretKeySpec(generatedSecret, "AES");
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(secretKeySpec);
                byte[] hkdfOutput = mac.doFinal(Base64.getEncoder().encodeToString(secretKey.getEncoded()).getBytes(StandardCharsets.UTF_8));
                System.arraycopy(hkdfOutput, 0, derivedKey, 0, 16);
            }

            secretKey = new SecretKeySpec(derivedKey, "AES");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error deriving key", e);
        }
    }

    private void generateKeys() {
        try {
            String curveName = "secp256r1";
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(curveName);
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    private String encrypt(String plaintext) {
        try {
            byte[] ivBytes = new byte[cipher.getBlockSize()];
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(ivBytes));
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
            byte[] combined = new byte[ivBytes.length + encryptedBytes.length];
            System.arraycopy(ivBytes, 0, combined, 0, ivBytes.length);
            System.arraycopy(encryptedBytes, 0, combined, ivBytes.length, encryptedBytes.length);
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during encryption", e);
            return null;
        }
    }

    private String decrypt(String encryptedText) {
        try {
            byte[] combined = Base64.getDecoder().decode(encryptedText);
            byte[] ivBytes = Arrays.copyOfRange(combined, 0, cipher.getBlockSize());
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(ivBytes));
            byte[] decryptedBytes = cipher.doFinal(combined, cipher.getBlockSize(), combined.length - cipher.getBlockSize());
            String plainText = new String(decryptedBytes, StandardCharsets.UTF_8);
            return plainText;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Not your message", e);
            return "";
        }
    }

    private void generateBumpFile() {
        // Write public key, initial receivingTag and initial receiving cell index to file
        byte[] pubKeyBytes = publicKey.getEncoded();
        String pubKeyString = Base64.getEncoder().encodeToString(pubKeyBytes);
        String tag = generateTag(TAG_LENGTH);
        receiveTag = tag;
        int randomIndex = generateRandomIndex();
        receiveCell = randomIndex;
        try (FileWriter writer = new FileWriter(name.toLowerCase() + "bump.txt")) {
            writer.write(pubKeyString+":"+randomIndex+":"+tag);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during generation bump file", e);
        }
    }

    private String getBumpName() {
        while (true) {
            File[] bumpFiles = new File(".").listFiles((dir, filename) -> filename.toLowerCase().endsWith("bump.txt") && !filename.toLowerCase().startsWith(name.toLowerCase()));
            if (bumpFiles != null && bumpFiles.length != 0) {
                String fileName = bumpFiles[0].getName();
                return fileName.substring(0, fileName.indexOf("bump.txt"));
            } else {
                try {
                    Thread.sleep(500);
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Error sleeping", e);
                }
            }
        }
    }

    private void getBumpFile(String nameOfPerson) {
        try {
            Path bumpFilePath = Path.of(nameOfPerson.toLowerCase() + "bump.txt");
            if (Files.exists(bumpFilePath)) {
                String fileContent = Files.readString(bumpFilePath);
                String[] parts = fileContent.split(":");

                byte[] pubKeyBytes = Base64.getDecoder().decode(parts[0]);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("EC");
                othersPublicKey = keyFactory.generatePublic(keySpec);

                sendCell = Integer.parseInt(parts[1]);
                sendTag = parts[2];
                deriveKey();

                Files.delete(bumpFilePath);
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error reading or deleting bump file", e);
        }
    }

    private int generateRandomIndex() {
        return random.nextInt(loadBalancer.MAX_CELL_NUMBER);
    }

    private String generateTag(int length) {
        StringBuilder stringBuilder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            stringBuilder.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        return stringBuilder.toString();
    }

    private String getHash(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = String.format("%02X", b);
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error creating hash", e);
        }
        return null;
    }

}
