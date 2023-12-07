package org.example;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.MessageDigest;
import java.util.*;

import java.util.logging.Level;
import java.util.logging.Logger;

public class ChatServerImpl extends UnicastRemoteObject implements ChatServerInterface {
    private HashMap<Integer, HashMap<String, String>> bulletinBoard;
    private static final Logger LOGGER = Logger.getLogger(Client.class.getName());
    private int messageCount;
    private final static int MAX_MESSAGE_COUNT = 10000;

    public ChatServerImpl() throws RemoteException {
        bulletinBoard = new HashMap<>();
        messageCount = 0;

    }

    @Override
    public boolean postMessage(int cell, String hashedTag, String message) throws RemoteException {
        synchronized (bulletinBoard) {
            bulletinBoard.computeIfAbsent(cell, k -> new HashMap<>());
        }
        synchronized (bulletinBoard.get(cell)) {
            if (bulletinBoard.get(cell).get(hashedTag) != null) return false;
            bulletinBoard.get(cell).put(hashedTag, message);
            messageCount++;
            return true;
        }
    }

    @Override
    public String getMessage(int cell, String tag) throws RemoteException {
        if (bulletinBoard.get(cell) == null) return null;

        boolean removeCell = false;
        String message = null;
        synchronized (bulletinBoard.get(cell)) {
            message = bulletinBoard.get(cell).get(getHash(tag));
            if (message != null) bulletinBoard.get(cell).remove(getHash(tag));
            if (bulletinBoard.get(cell).isEmpty()) removeCell = true;
            messageCount--;
        }
        synchronized (bulletinBoard) {
            if (removeCell) {
                bulletinBoard.remove(cell);
            }
        }
        return message;
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
            return null;
        }
    }

    public boolean isFull() {
        return messageCount >= (MAX_MESSAGE_COUNT*0.9);
    }

    public boolean cellContainsTag(int cell, String tag) {
        try {
            if (getMessage(cell, tag) != null) return true;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error checking if tag exists in cell", e);
        }
        return false;
    }

    @Override
    public boolean isEmpty() throws RemoteException {
        return bulletinBoard.isEmpty();
    }
}
