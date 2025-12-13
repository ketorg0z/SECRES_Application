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

public class VPN extends VpnService {

    public static final String ACTION_PACKET_RECEIVED =
            "com.example.analyseurtrafic.PACKET_RECEIVED";
    public static final String EXTRA_PACKET_INFO = "packet_info";

    private static final String TAG = "VPN-Analyzer";

    private ParcelFileDescriptor vpnInterface;
    private Thread vpnThread;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        vpnThread = new Thread(this::runVpn);
        vpnThread.start();
        return START_STICKY;
    }

    private void runVpn() {
        try {
            Builder builder = new Builder();
            builder.setSession("TrafficAnalyzer");
            builder.addAddress("10.0.0.2", 24);
            builder.addRoute("0.0.0.0", 0);

            vpnInterface = builder.establish();
            if (vpnInterface == null) return;

            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());

            byte[] buffer = new byte[32767];

            while (true) {
                int length = in.read(buffer);
                if (length > 0) {

                    String info = parsePacket(buffer, length);
                    sendToUI(info);

                    out.write(buffer, 0, length);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "VPN error", e);
        }
    }

    private String parsePacket(byte[] data, int length) {
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

    // ================= IPv4 =================
    private String parseIPv4(IpV4Packet ip) {

        int proto = ip.getHeader().getProtocol().value();
        String src = ip.getHeader().getSrcAddr().getHostAddress();
        String dst = ip.getHeader().getDstAddr().getHostAddress();

        if (proto == 6) { // TCP
            TcpPacket tcp = ip.get(TcpPacket.class);
            int sport = tcp.getHeader().getSrcPort().valueAsInt();
            int dport = tcp.getHeader().getDstPort().valueAsInt();
            return "IPv4 | TCP | " + src + ":" + sport + " → " + dst + ":" + dport +
                    identifyAppProtocol(dport);

        } else if (proto == 17) { // UDP
            UdpPacket udp = ip.get(UdpPacket.class);
            int sport = udp.getHeader().getSrcPort().valueAsInt();
            int dport = udp.getHeader().getDstPort().valueAsInt();
            return "IPv4 | UDP | " + src + ":" + sport + " → " + dst + ":" + dport +
                    identifyAppProtocol(dport);

        } else if (proto == 1) { // ICMPv4
            return "IPv4 | ICMP | " + src + " → " + dst;
        }

        return "IPv4 | Protocol " + proto + " | " + src + " → " + dst;
    }

    // ================= IPv6 =================
    private String parseIPv6(IpV6Packet ip) {

        int proto = ip.getHeader().getNextHeader().value();
        String src = ip.getHeader().getSrcAddr().getHostAddress();
        String dst = ip.getHeader().getDstAddr().getHostAddress();

        if (proto == 6) { // TCP
            TcpPacket tcp = ip.get(TcpPacket.class);
            int sport = tcp.getHeader().getSrcPort().valueAsInt();
            int dport = tcp.getHeader().getDstPort().valueAsInt();
            return "IPv6 | TCP | " + src + ":" + sport + " → " + dst + ":" + dport +
                    identifyAppProtocol(dport);

        } else if (proto == 17) { // UDP
            UdpPacket udp = ip.get(UdpPacket.class);
            int sport = udp.getHeader().getSrcPort().valueAsInt();
            int dport = udp.getHeader().getDstPort().valueAsInt();
            return "IPv6 | UDP | " + src + ":" + sport + " → " + dst + ":" + dport +
                    identifyAppProtocol(dport);

        } else if (proto == 58) { // ICMPv6
            return "IPv6 | ICMPv6 | " + src + " → " + dst;
        }

        return "IPv6 | Protocol " + proto + " | " + src + " → " + dst;
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

    @Override
    public void onDestroy() {
        super.onDestroy();
        try {
            if (vpnInterface != null) vpnInterface.close();
        } catch (IOException ignored) {}
    }
}
