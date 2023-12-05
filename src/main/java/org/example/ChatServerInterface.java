package org.example;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface ChatServerInterface extends Remote {
    void postMessage(int cell, String hashedTag, String message) throws RemoteException;
    String getCell(int cell, String tag) throws RemoteException;
}
