#include <WiFi.h>
#include <Wire.h>
#include <Arduino.h>
#include <ESP8266SAM.h>
#include <AudioOutputI2S.h>
#include <M5Stack.h>

#include "esp_wifi.h"

#define maxCh 13 //max Channel -> US = 11, EU = 13, Japan = 14

AudioOutputI2S *out = NULL;
ESP8266SAM *sam = new ESP8266SAM;

int curChannel = 1;
int listcount = 0;

const int maxdevices = 32;
String maclist[maxdevices][3];

const int numDevices = 5;
String KnownMac[numDevices][2] = {  // address list
    {"device1", 		"A76B8F17FC3E"},
    {"device2", 		"D8C68F17FB90"},
    {"device3", 		"64408F17FB9E"},
    {"device4", 		"48F89EF9EFF1"},
    {"device5", 		"FFB9EF8FEF68"}
};

String defaultTTL = "60"; // Maximum time (Apx seconds) elapsed before device is consirded offline

const wifi_promiscuous_filter_t filt = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
};

typedef struct {
    uint8_t mac[6];
} __attribute__((packed)) MacAddr;

typedef struct {
    int16_t fctl;
    int16_t duration;
    MacAddr da;
    MacAddr sa;
    MacAddr bssid;
    int16_t seqctl;
    unsigned char payload[];
} __attribute__((packed)) WifiMgmtHdr;


// #################################################################
// #################################################################
void setup() {
    M5.begin();
    Serial.begin(115200);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&sniffer);
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);

    out = new AudioOutputI2S(0, 1);
    out->begin();
    out->SetGain(0.25); // fp number between 0.0 and 4.0
    M5.Lcd.setTextFont(1);
    M5.Lcd.print("Started");

}


// #################################################################
// #################################################################
void SELECT_VOICE(int voice, bool smode)
{
    sam->SetSingMode(smode);
    switch (voice)
    {
        case 0: //  Elf
            sam->SetSpeed(72);
            sam->SetPitch(64);
            sam->SetThroat(110);
            sam->SetMouth(160);
            break;
        case 1: // Robot
            sam->SetSpeed(92);
            sam->SetPitch(60);
            sam->SetThroat(190);
            sam->SetMouth(190);
            break;
        case 2: // Stuffy
            sam->SetSpeed(82);
            sam->SetPitch(72);
            sam->SetThroat(110);
            sam->SetMouth(105);
            break;
        case 3: // Old Lady
            sam->SetSpeed(82);
            sam->SetPitch(32);
            sam->SetThroat(145);
            sam->SetMouth(145);
            break;
        case 4: // ET
            sam->SetSpeed(100);
            sam->SetPitch(64);
            sam->SetThroat(150);
            sam->SetMouth(200);
            break;
        case 5: // Sam
            sam->SetSpeed(72);
            sam->SetPitch(64);
            sam->SetThroat(128);
            sam->SetMouth(128);
            break;
    }
}


// #################################################################
// #################################################################
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) { //This is where packets end up after they get sniffed
    wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buf;
    int len = p->rx_ctrl.sig_len;
    WifiMgmtHdr *wh = (WifiMgmtHdr*)p->payload;
    len -= sizeof(WifiMgmtHdr);
    if (len < 0) {
        Serial.println("Received 0");
        return;
    }
    String packet;
    String mac;
    int fctl = ntohs(wh->fctl);
    for (int i = 8; i <= 8 + 6 + 1; i++) { // This reads the first couple of bytes of the packet. This is where you can read the whole packet replaceing the "8+6+1" with "p->rx_ctrl.sig_len"
        packet += String(p->payload[i], HEX);
    }
    int plen = packet.length();
    if (plen != 16) return;
    for (int i = 4; i <= 15; i++) { // This removes the 'nibble' bits from the stat and end of the data we want. So we only get the mac address.
        mac += packet[i];
    }
    mac.toUpperCase();

    int added = 0;
    for (int i = 0; i < maxdevices; i++) { // checks if the MAC address has been added before
        if (mac == maclist[i][0]) {
            maclist[i][1] = defaultTTL;
            if (maclist[i][2] == "OFFLINE") {
                maclist[i][2] = "0";
            }
            added = 1;
        }
    }

    if (added == 0) { // If its new. add it to the array.
        maclist[listcount][0] = mac;
        maclist[listcount][1] = defaultTTL;
        // Serial.println(mac);
        listcount++;
        if (listcount > maxdevices) {
            Serial.println("Too many addresses");
            listcount = 0;
        }
    }

}


// #################################################################
// #################################################################
void purge() { // This manages the TTL
    for (int i = 0; i < listcount; i++) {
        if (!(maclist[i][0] == "")) {
            int ttl = (maclist[i][1].toInt());
            ttl--;
            if (ttl <= 0) {
                //Serial.println("OFFLINE: " + maclist[i][0]);
                maclist[i][2] = "OFFLINE";
                maclist[i][1] = defaultTTL;
            } else {
                maclist[i][1] = String(ttl);
            }
        }
    }
}


// #################################################################
// #################################################################
void updatetime() { // This updates the time the device has been online for
    for (int i = 0; i < listcount; i++) {
        if (!(maclist[i][0] == "")) {
            if (maclist[i][2] == "")maclist[i][2] = "0";
            if (!(maclist[i][2] == "OFFLINE")) {
                int timehere = (maclist[i][2].toInt());
                timehere ++;
                maclist[i][2] = String(timehere);
            }
            //Serial.println(maclist[i][0] + " : " + maclist[i][2]);
        }
    }
}


// #################################################################
// #################################################################
void showpeople() { // This checks if the MAC is in the reckonized list and then displays it on the OLED and/or prints it to serial.

    String forScreen = "";
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 0);
    for (int i = 0; i < listcount; i++) {
        String tmp1 = maclist[i][0];
        Serial.print(maclist[i][0] + " : " + maclist[i][1] + " : " + maclist[i][2]);
        M5.Lcd.print(maclist[i][0] + " : " + maclist[i][1] + " : " + maclist[i][2]);
        if (!(tmp1 == "")) {
            out->begin();
            ESP8266SAM *sam = new ESP8266SAM;
            SELECT_VOICE(1, 1);
            for (int j = 0; j < numDevices; j++) {
                String tmp2 = KnownMac[j][1];
                if (tmp1 == tmp2) {
                    forScreen += (KnownMac[j][0] + " : " + maclist[i][2] + "\n");

                    String device_owner = (KnownMac[j][0] + " de. techted.");
                    char buf[35];
                    device_owner.toCharArray(buf, 35);
                    M5.Lcd.print(" : " + KnownMac[j][0]);
                    Serial.print(" : " + KnownMac[j][0]);
                    //sam->Say(out, buf);
                }
            }
            delete sam;
            out->stop();
        }
        Serial.println();
        M5.Lcd.println();
    }
    Serial.println("################################################");
}


// #################################################################
// #################################################################
void loop() {
    //Serial.println("Changed channel:" + String(curChannel));
    while (curChannel <= maxCh)
    {
        esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);

        updatetime();
        purge();
        curChannel++;
        showpeople();

        delay(1000);
    }
    curChannel = 1;
}
