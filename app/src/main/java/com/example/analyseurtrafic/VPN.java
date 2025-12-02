package com.example.analyseurtrafic;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class VPN extends VpnService {

    public static final String ACTION_PACKET_RECEIVED = "com.example.analyseurtrafic.PACKET_RECEIVED";
    public static final String EXTRA_PACKET_INFO = "packet_info";

    private static final String TAG = "MyVPN";
    private ParcelFileDescriptor vpnInterface = null;
    private Thread vpnThread;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        vpnThread = new Thread(() -> {
            try {
                runVpn();
            } catch (Exception e) {
                Log.e(TAG, "Error running VPN", e);
                if (!(e instanceof InterruptedException)) {
                    e.printStackTrace();
                }
            } finally {
                stopVpn();
            }
        });
        vpnThread.start();
        return START_STICKY;
    }

    private void runVpn() throws Exception {
        // 1. Configure the VPN interface
        Builder builder = new Builder();
        builder.setSession("AnalyseurTrafic");
        builder.addAddress("10.0.0.2", 24); // Internal IP address for the VPN interface
        builder.addRoute("0.0.0.0", 0);   // Route all traffic through the VPN

        // 2. Establish the VPN interface
        vpnInterface = builder.establish();
        if (vpnInterface == null) {
            Log.e(TAG, "VPN interface not established");
            return;
        }

        // 3. Get the input and output streams
        FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());

        // 4. Start reading and writing packets (the core logic of your packet analyzer)
        // For now, this loop will just read packets and log their size.
        byte[] packet = new byte[32767];
        while (true) {
            int length = in.read(packet);
            if (length > 0) {

                String packetInfo = "Received packet of size: " + length;

                Intent intent = new Intent(ACTION_PACKET_RECEIVED);
                intent.putExtra(EXTRA_PACKET_INFO, packetInfo);
                LocalBroadcastManager.getInstance(this).sendBroadcast(intent);

                // Here you would parse the packet headers and analyze the data
                Log.d(TAG, "Received packet of size: " + length);
                // For a simple start, you can just write the packet back to the interface
                // to allow traffic to flow.
                out.write(packet, 0, length);
            }
        }
    }

    private void stopVpn() {
        if (vpnThread != null) {
            vpnThread.interrupt();
        }
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException e) {
                Log.e(TAG, "Error closing VPN interface", e);
            }
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        stopVpn();
    }
}

