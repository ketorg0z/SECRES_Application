package com.example.analyseurtrafic;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.factory.PacketFactoryBinder;


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
                String packetInfo;
                try {
                    byte[] capturedPacketBytes = new byte[length];
                    System.arraycopy(packet, 0, capturedPacketBytes, 0, length);
                    // 2. Use pcap4j's factory to create a Packet object from the raw bytes.
                    Packet parsedPacket = PacketFactories.getFactory(Packet.class, IpNumber.class)
                            .newInstance(capturedPacketBytes, 0, capturedPacketBytes.length, IpNumber.IPV4);

                    IpPacket ipPacket = parsedPacket.get(IpPacket.class);
                    if (ipPacket != null) {
                        String protocol = ipPacket.getHeader().getProtocol().name();
                        String srcAddr = ipPacket.getHeader().getSrcAddr().getHostAddress();
                        String dstAddr = ipPacket.getHeader().getDstAddr().getHostAddress();
                        String portInfo = "";

                        if (protocol.equals("TCP")) {
                            TcpPacket tcpPacket = ipPacket.get(TcpPacket.class);
                            int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
                            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
                            portInfo = " | " + srcPort + " -> " + dstPort;
                        } else if (protocol.equals("UDP")) {
                            UdpPacket udpPacket = ipPacket.get(UdpPacket.class);
                            int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
                            int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
                            portInfo = " | " + srcPort + " -> " + dstPort;
                        }

                        packetInfo = protocol + " | " + srcAddr + " -> " + dstAddr + portInfo;

                    } else {
                        packetInfo = "Non-IP Packet - Size: " + length;
                    }

                } catch (Exception e) {
                    packetInfo = "Malformed Packet - Size: " + length;
                    Log.e(TAG, "Error parsing packet", e);
                }

                Intent intent = new Intent(ACTION_PACKET_RECEIVED);
                intent.putExtra(EXTRA_PACKET_INFO, packetInfo);
                LocalBroadcastManager.getInstance(this).sendBroadcast(intent);

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

