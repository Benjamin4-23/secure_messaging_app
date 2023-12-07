package org.example;

public class ClientThread extends Thread {
    @Override
    public void run() {
        Client client = new Client();
    }
}