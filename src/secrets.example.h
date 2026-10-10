#pragma once
// Copy this file to secrets.h and fill in your WiFi credentials.
// secrets.h is gitignored so your credentials never get committed.
static const char* WIFI_SSID = "YOUR_WIFI_SSID";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

// Auth for the dashboard's state-changing endpoints (/ban, /addblock, /upload,
// /update, /setupdate, /forgetwifi) and for network OTA (ArduinoOTA).
//
// ⚠️ 102030Zz is a PUBLIC default — this file ships in the open repo, so anyone
// who has seen the project knows it. It only stops strangers who have never
// heard of c3-adblock. For real security, build from a local secrets.h (this
// exact file, gitignored) with values that have never been published; the
// dashboard shows an orange warning for as long as a public default is in use.
static const char* WEB_USER = "admin";
static const char* WEB_PASS = "102030Zz";
static const char* OTA_PASS = "102030Zz";
