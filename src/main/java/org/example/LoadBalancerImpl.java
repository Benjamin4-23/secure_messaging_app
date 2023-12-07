package org.example;

import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class LoadBalancerImpl extends UnicastRemoteObject implements LoadBalancerInterface {
    private List<ChatServerInterface> serverConnections;
    private static final Logger LOGGER = Logger.getLogger(LoadBalancerImpl.class.getName());

    public LoadBalancerImpl() throws RemoteException {
        serverConnections = new ArrayList<>();
        checkExtraServers();
    }

    public boolean postMessage(int cell, String hashedTag, String message) throws RemoteException {
        for (ChatServerInterface server : serverConnections) {
            if (!server.isFull()) {
                boolean gelukt = server.postMessage(cell, hashedTag, message);
                if (gelukt) return true;
            }
        }
        checkExtraServers();
        return false;
    }

    public String getMessage(int cell, String tag) throws RemoteException {
        for (ChatServerInterface server : serverConnections) {
            String message = server.getMessage(cell, tag);
            if (message != null) {
                checkReduceServers();
                return message;
            }
        }
        return null;
    }

    private void checkExtraServers() {
        try {
            for (ChatServerInterface server : serverConnections) {
                if (!server.isFull()) return;
            }
            ChatServerInterface server = new ChatServerImpl();
            java.rmi.Naming.rebind("ChatServer"+ serverConnections.size(), server);
            serverConnections.add((ChatServerInterface) Naming.lookup("rmi://localhost/ChatServer"+serverConnections.size()));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error checking if there is a need for extra servers", e);
        }
    }

    private void checkReduceServers() {
        try {
            int emptyServers = 0;
            int fullServers = 0;
            for (ChatServerInterface server : serverConnections) {
                if (server.isEmpty()) emptyServers++;
                if (server.isFull()) fullServers++;
            }
            if (emptyServers > 0 && fullServers < serverConnections.size()-2) {
                ChatServerInterface removedServer = serverConnections.remove(serverConnections.size() - 1);
                java.rmi.Naming.unbind("rmi://localhost/" + removedServer);
                UnicastRemoteObject.unexportObject(removedServer, true);
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error checking if extra servers can be removed", e);
        }
    }
}
