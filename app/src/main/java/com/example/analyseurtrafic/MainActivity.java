package com.example.analyseurtrafic;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.ListView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.util.ArrayList;

public class MainActivity extends AppCompatActivity {

    private static final int VPN_REQUEST_CODE = 0;

    private ListView packetListView;
    private ArrayAdapter<String> packetAdapter;
    private ArrayList<String> packetList;

    private BroadcastReceiver packetReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent != null && VPN.ACTION_PACKET_RECEIVED.equals(intent.getAction())) {
                String packetInfo = intent.getStringExtra(VPN.EXTRA_PACKET_INFO);
                if (packetInfo != null) {
                    packetList.add(0, packetInfo); // Add to top of the list
                    packetAdapter.notifyDataSetChanged();
                }
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        packetListView = findViewById(R.id.packet_list);
        packetList = new ArrayList<>();
        packetAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, packetList);
        packetListView.setAdapter(packetAdapter);

        // Automatically start the VPN connection process
        Intent vpnIntent = VpnService.prepare(getApplicationContext());
        if (vpnIntent != null) {
            // This is the first time. Ask the user for permission.
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
        } else {
            // Permission has already been granted.
            onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            // Permission granted, start the VPN service
            Intent intent = new Intent(this, VPN.class);
            startService(intent);
        } else {
            packetList.add(0, "Error: Permission not granted");
            packetAdapter.notifyDataSetChanged();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Register the receiver to get updates from the VPN service
        LocalBroadcastManager.getInstance(this).registerReceiver(
                packetReceiver, new IntentFilter(VPN.ACTION_PACKET_RECEIVED));
    }

    @Override
    protected void onPause() {
        super.onPause();
        // Unregister the receiver to avoid memory leaks
        LocalBroadcastManager.getInstance(this).unregisterReceiver(packetReceiver);
    }
}