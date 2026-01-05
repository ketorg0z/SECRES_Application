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
    private boolean isPaused = false;
    private android.widget.Button pauseButton;

    private BroadcastReceiver packetReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent != null && VPN.ACTION_PACKET_RECEIVED.equals(intent.getAction())) {
                String packetInfo = intent.getStringExtra(VPN.EXTRA_PACKET_INFO);
                if (packetInfo != null && !isPaused) {

                    // 1. Check if the user is currently looking at the very top of the list
                    // getFirstVisiblePosition() returns the index of the top-most visible cell
                    boolean isAtTop = packetListView.getFirstVisiblePosition() == 0;

                    // 2. Add the data to the list source
                    // We check first to prevent the list from growing indefinitely (optional optimization)
                    if (packetList.size() > 1000) {
                        packetList.remove(packetList.size() - 1);
                    }
                    packetList.add(0, packetInfo);

                    // 3. Handle the UI update based on scroll position
                    if (isAtTop) {
                        // Scenario A: User is watching the live feed at the top.
                        // We update the view and ensure it stays snapped to the top.
                        packetAdapter.notifyDataSetChanged();
                        packetListView.setSelection(0);
                    } else {
                        // Scenario B: User has scrolled down to inspect specific packets.
                        // We need to update the data WITHOUT moving the user's screen.

                        // Capture the exact position of the top visible item
                        android.view.View v = packetListView.getChildAt(0);
                        int top = (v == null) ? 0 : (v.getTop() - packetListView.getPaddingTop());
                        int index = packetListView.getFirstVisiblePosition();

                        // Update the adapter (this usually resets position)
                        packetAdapter.notifyDataSetChanged();

                        // Force restore the exact scroll position.
                        // We use (index + 1) because we just added a new item at index 0,
                        // so the item the user was looking at has moved down by 1.
                        packetListView.setSelectionFromTop(index + 1, top);
                    }
                }
            }
        }
    };


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        pauseButton = findViewById(R.id.pause_btn);

        pauseButton.setOnClickListener(v -> {
            // Toggle the state
            isPaused = !isPaused;

            // Update the text so the user knows what happened
            if (isPaused) {
                pauseButton.setText("Resume UI");
            } else {
                pauseButton.setText("Pause UI");
            }
        });

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