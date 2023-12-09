package org.example;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface LoadBalancerInterface extends Remote {
    Integer MAX_CELL_NUMBER = 500;
    void postMessage(int cell, String hashedTag, String message) throws RemoteException;
    List<String> getMessage(int cell, String tag) throws RemoteException;
}
