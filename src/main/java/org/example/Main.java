package org.example;

import java.rmi.RemoteException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {
    public static void main(String[] args) {
        Logger LOGGER = Logger.getLogger("Main");
        try {
            java.rmi.registry.LocateRegistry.createRegistry(1099);
            LoadBalancerInterface loadBalancer = new LoadBalancerImpl();
            java.rmi.Naming.rebind("LoadBalancer", loadBalancer);

            for (int i = 0; i < 2; i++) {
                Thread client = new ClientThread();
                client.start();
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error checking if there is a need for extra servers", e);
        }

    }
}