package org.example;

// Press Shift twice to open the Search Everywhere dialog and type `show whitespaces`,
// then press Enter. You can now see whitespace characters in your code.
public class Main {
    public static void main(String[] args) {
        try {
            LoadBalancerInterface loadBalancer = new LoadBalancer();
            java.rmi.registry.LocateRegistry.createRegistry(0);
            java.rmi.Naming.rebind("LoadBalancer", loadBalancer);

            Client c1 = new Client();
            Client c2 = new Client();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }
}