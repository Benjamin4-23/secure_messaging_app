package org.example;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface ChatServerInterface extends Remote {
    boolean postMessage(int cell, String hashedTag, String message) throws RemoteException;
    String getMessage(int cell, String tag) throws RemoteException;
    boolean isFull() throws RemoteException;
    boolean isEmpty() throws RemoteException;
}
