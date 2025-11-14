# Quick Start Guide - Device Management Features

## 🚀 Getting Started

Your Router Dashboard now includes three powerful device management features:

### 1. ✏️ **Edit Device Names**
Customize device names for easier identification on your network.

**Steps:**
1. Go to the **Connected Devices** tab
2. Click the **✏️ Edit button** on any device
3. A modal dialog opens with the device details
4. Update the **Device Name** and/or **Device Type**
5. Click **Save Changes** (or press Enter)
6. The device name is saved and will persist across sessions

**Example:**
- Before: `192.168.8.105` (Unknown)
- After: `Living Room TV` (Smart TV)

---

### 2. 🆕 **New Device Badges**
Automatically identify newly discovered devices on your network.

**Features:**
- Devices discovered for the first time appear with a **🆕 NEW badge**
- A yellow banner appears at the top showing all new devices
- New devices are highlighted for quick identification
- Once you edit a device, it's marked as known

**Visual Indicators:**
- 🆕 Badge on device card
- Yellow summary banner with list of new devices
- Positioning at top of device list

**What triggers "NEW" status:**
- Device first appears in router's DHCP leases
- System automatically creates a database record
- `is_new` flag set to true

---

### 3. 🔒 **Block/Unblock Devices**
Control network access for specific devices.

**Steps:**
1. Locate the device you want to block/unblock
2. Click the **🔒 Lock button** to block (or 🔓 Unlock button to unblock)
3. The device status updates immediately
4. Blocked devices appear faded with reduced opacity
5. Status persists across sessions

**Button Indicators:**
- 🔒 **Lock icon**: Device is allowed on network (click to block)
- 🔓 **Unlock icon**: Device is blocked from network (click to unblock)
- Button color changes: Yellow when active, Red when blocked

**Visual Changes for Blocked Devices:**
- Device card appears with reduced opacity
- Red left border instead of green
- 🚫 Icon shows in device name area
- Card styling indicates blocked status

---

## 📊 Connected Devices Tab Layout

```
┌─────────────────────────────────────────────────┐
│ Connected Devices (14)        [Refresh List]   │
├─────────────────────────────────────────────────┤
│                                                 │
│ 🆕 2 New Devices Discovered:                   │
│ [🆕 Samsung-Smart-Fridge] [🆕 iPhone-14]      │
│                                                 │
├─────────────────────────────────────────────────┤
│                                                 │
│ ✅ Living Room TV                              │
│ 📶 192.168.8.105                               │
│ 🔗 AA:BB:CC:DD:EE:FF                           │
│                     [✏️] [🔒]  (Edit, Block)   │
│ Details:                                        │
│ • Connected: 2 hours 30 min                    │
│ • Bandwidth: 5GHz                              │
│ • Type: Smart TV                               │
│ • Status: Online                               │
│                                                 │
├─────────────────────────────────────────────────┤
│                                                 │
│ ❌ Old Security Camera (BLOCKED)                │
│ 📊 192.168.8.203                               │
│ 🔗 11:22:33:44:55:66                           │
│ [Faded appearance] [✏️] [🔓]  (Edit, Unblock) │
│ Details:                                        │
│ • Connected: Offline                           │
│ • Type: Security Device                        │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

## 📝 Edit Device Modal

When you click **✏️ Edit**, a modal dialog appears:

```
┌──────────────────────────────────────────┐
│ ✏️ Edit Device                         │
├──────────────────────────────────────────┤
│                                          │
│ MAC Address                              │
│ [AA:BB:CC:DD:EE:FF] (Read-only)         │
│                                          │
│ Device Name                              │
│ [Living Room TV                    ]    │
│                                          │
│ Device Type                              │
│ [Smart TV                         ]    │
│                                          │
│  [Save Changes]      [Cancel]           │
│                                          │
└──────────────────────────────────────────┘
```

---

## 🎮 Interactive Features

### Drag & Drop (Advanced)
Device cards are draggable for future extensibility:
- Hover over a device card to see it's draggable
- Click and hold to drag
- Release to drop
- Currently shows visual feedback for drag operations

### Keyboard Shortcuts
While editing a device:
- **Enter**: Save changes
- **Escape**: Close modal (or click outside)

### Notifications
After any action:
- ✅ Green notification: "Device updated successfully!"
- ℹ️ Gray notification: Status updates
- Auto-dismisses after 3 seconds

---

## 🔧 Technical Details

### Database Schema
Each device is tracked with:
- **MAC Address**: Unique device identifier
- **Custom Name**: User-defined device name
- **Device Type**: Category (Smartphone, Laptop, Smart TV, etc.)
- **Blocked Status**: Whether device can access network
- **New Flag**: Whether device was recently discovered
- **First Seen**: When device first appeared
- **Last Seen**: Last network activity timestamp
- **Notes**: Additional user notes

### API Endpoints (Behind the scenes)
- `GET /api/connected-devices` - Get all devices with management data
- `PUT /api/device/{mac_address}` - Update device information
- `GET /api/devices/new` - Get newly discovered devices
- `POST /api/device/{mac_address}/block` - Block a device
- `POST /api/device/{mac_address}/unblock` - Unblock a device

All endpoints require authentication and are protected.

---

## 💡 Tips & Tricks

1. **Quick Device Identification**
   - Edit device names immediately when new devices appear
   - Use consistent naming convention (e.g., "Living Room TV", "Master Bedroom Camera")

2. **Network Security**
   - Use the block feature for guest devices or IoT devices you want to temporarily disable
   - Block suspicious new devices until identified

3. **Monitoring New Devices**
   - Check the new devices section regularly
   - The 🆕 badge helps spot unauthorized devices

4. **Persistent Configuration**
   - All settings persist across browser refreshes
   - Device names and block status stored in database
   - Manual device edits take precedence over auto-detection

5. **Bulk Management** (Future)
   - Currently manage devices one at a time
   - Future updates may include bulk operations

---

## ⚙️ Configuration

### Auto-Refresh
Connected Devices list auto-refreshes every 30 seconds:
- Click **Refresh List** for immediate update
- Shows last update time at bottom

### Status Updates
Device status checked in real-time:
- ✅ Online devices show green indicators
- ❌ Offline devices show red indicators
- Bandwidth info updates automatically

---

## 🆘 Troubleshooting

### Issue: Device name not saving
**Solution:**
1. Check internet connection
2. Look for error message in browser console (F12)
3. Try saving again
4. Refresh the page

### Issue: NEW badge not appearing
**Solution:**
1. Manually refresh device list
2. Ensure device is truly new (not previously seen)
3. Check database connection

### Issue: Cannot block/unblock
**Solution:**
1. Verify you're still logged in
2. Check user has admin permissions
3. Try refreshing the page
4. Check browser console for errors

### Issue: Modal won't open
**Solution:**
1. Press F12 and check browser console
2. Try clicking elsewhere on page first
3. Refresh and try again
4. Check browser JavaScript is enabled

---

## 📱 Mobile Support

Connected Devices works on mobile browsers:
- Touch-friendly buttons and interface
- Modal adjusts to screen size
- Swipe-friendly device list
- Responsive design adapts to all screen sizes

---

## 🔐 Security Notes

- All device operations require authentication
- Device settings saved securely in database
- Changes visible only to logged-in user
- No data shared between users
- Block status enforced by router (backend)

---

## 🚀 What's Next?

Future enhancements planned:
- ⏰ Schedule automatic blocking times
- 📊 Bandwidth limits per device
- 📈 Activity monitoring and statistics
- 👥 Device groups and categories
- 🔔 Notifications for new devices
- 📋 Export/import device configurations

---

## 📞 Support

For issues or questions:
1. Check this guide
2. Review browser console (F12)
3. Check server logs
4. Refer to DEVICE_MANAGEMENT_FEATURES.md for technical details

Enjoy your enhanced Router Dashboard! 🎉
