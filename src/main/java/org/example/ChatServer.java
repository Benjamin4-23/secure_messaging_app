package org.example;

import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.MessageDigest;
import java.util.*;

public class ChatServer extends UnicastRemoteObject implements ChatServerInterface {
    private List<HashMap<String, String>> bulletinBoard;

    public ChatServer() throws RemoteException {
        bulletinBoard = new ArrayList<>();
        // 500 plaatsen initialiseren, later Integer keys vervangen door hashes
        for (int i = 0; i < 500; i++) {
            bulletinBoard.add(i, new HashMap<>());
        }
    }

    @Override
    public void postMessage(int cell, String tag, String message) throws RemoteException {
        synchronized (bulletinBoard.get(cell)) {
            bulletinBoard.get(cell).put(tag, message);
        }
    }

    @Override
    public String getCell(int cell, String tag) throws RemoteException {
        synchronized (bulletinBoard.get(cell)) {
            String message = bulletinBoard.get(cell).get(getHash(tag));
            if (message != null) bulletinBoard.get(cell).remove(getHash(tag));
            return message;
        }
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
        } catch(Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
