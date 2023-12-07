package org.example;

import java.rmi.RemoteException;

public class Main {
    public static void main(String[] args) {
        try {
            java.rmi.registry.LocateRegistry.createRegistry(1099);
            LoadBalancerInterface loadBalancer = new LoadBalancerImpl();
            java.rmi.Naming.rebind("LoadBalancer", loadBalancer);

            for (int i = 0; i < 2; i++) {
                Thread client = new ClientThread();
                client.start();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }
}