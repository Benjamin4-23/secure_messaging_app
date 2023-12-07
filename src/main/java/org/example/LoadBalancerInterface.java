package org.example;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface LoadBalancerInterface extends Remote {
    public static Integer MAX_CELL_NUMBER = 500;
    public boolean postMessage(int cell, String hashedTag, String message) throws RemoteException;
    public String getMessage(int cell, String tag) throws RemoteException;
}
