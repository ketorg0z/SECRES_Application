package com.example.analyseurtrafic;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;


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
        try {
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

            byte[] buffer = new byte[32767];

            while (true) {
                int length = in.read(buffer);
                if (length > 0) {

                    String info = defineIPVersion(buffer, length);
                    sendToUI(info);

                    out.write(buffer, 0, length);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "VPN error", e);
        }
    }

    private String defineIPVersion(byte[] data, int length) {
        try {
            Packet packet;

            // Detect IPv4 or IPv6
            if ((data[0] >> 4) == 4) {
                packet = IpV4Packet.newPacket(data, 0, length);
                return parseIPv4((IpV4Packet) packet);
            } else if ((data[0] >> 4) == 6) {
                packet = IpV6Packet.newPacket(data, 0, length);
                return parseIPv6((IpV6Packet) packet);
            } else {
                return "Unknown L3 Packet";
            }

        } catch (Exception e) {
            return "Malformed packet (" + length + " bytes)";
        }
    }

    private String parseIPv4(IpV4Packet ip) {

        int protocol = ip.getHeader().getProtocol().value();
        String src = ip.getHeader().getSrcAddr().getHostAddress();
        String dst = ip.getHeader().getDstAddr().getHostAddress();

        if (protocol == 6) { // TCP
            TcpPacket tcp = ip.get(TcpPacket.class);
            int sport = tcp.getHeader().getSrcPort().valueAsInt();
            int dport = tcp.getHeader().getDstPort().valueAsInt();
            return "IPv4 | TCP | " + src + ":" + sport + " → " + dst + ":" + dport +
                    identifyAppProtocol(dport);

        } else if (protocol == 17) { // UDP
            UdpPacket udp = ip.get(UdpPacket.class);
            int sport = udp.getHeader().getSrcPort().valueAsInt();
            int dport = udp.getHeader().getDstPort().valueAsInt();
            return "IPv4 | UDP | " + src + ":" + sport + " → " + dst + ":" + dport +
                    identifyAppProtocol(dport);

        } else if (protocol == 1) { // ICMPv4
            return "IPv4 | ICMP | " + src + " → " + dst;
        }

        return "IPv4 | Protocol " + protocol + " | " + src + " → " + dst;
    }

    // ================= IPv6 =================
    private String parseIPv6(IpV6Packet ip) {

        int protocol = ip.getHeader().getNextHeader().value();
        String src = ip.getHeader().getSrcAddr().getHostAddress();
        String dst = ip.getHeader().getDstAddr().getHostAddress();

        if (protocol == 6) { // TCP
            TcpPacket tcp = ip.get(TcpPacket.class);
            int sport = tcp.getHeader().getSrcPort().valueAsInt();
            int dport = tcp.getHeader().getDstPort().valueAsInt();
            return "IPv6 | TCP | " + src + ":" + sport + " → " + dst + ":" + dport +
                    identifyAppProtocol(dport);

        } else if (protocol == 17) { // UDP
            UdpPacket udp = ip.get(UdpPacket.class);
            int sport = udp.getHeader().getSrcPort().valueAsInt();
            int dport = udp.getHeader().getDstPort().valueAsInt();
            return "IPv6 | UDP | " + src + ":" + sport + " → " + dst + ":" + dport +
                    identifyAppProtocol(dport);

        } else if (protocol == 58) { // ICMPv6
            return "IPv6 | ICMPv6 | " + src + " → " + dst;
        }

        return "IPv6 | Protocol " + protocol + " | " + src + " → " + dst;
    }

    // ================= App-layer identification =================
    private String identifyAppProtocol(int port) {
        if (port == 80) return " (HTTP)";
        if (port == 443) return " (HTTPS)";
        if (port == 53) return " (DNS)";
        if (port == 123) return " (NTP)";
        return "";
    }

    private void sendToUI(String text) {
        Intent intent = new Intent(ACTION_PACKET_RECEIVED);
        intent.putExtra(EXTRA_PACKET_INFO, text);
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
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

