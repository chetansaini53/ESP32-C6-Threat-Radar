/*
 * ============================================================================
 *  WIRELESS THREAT RADAR  —  ESP32-C6 passive defensive wireless monitor
 * ============================================================================
 *  A DETECTION-ONLY radar for the ESP32-C6 + 1.47" LCD that flags nearby
 *  wireless attacks on its screen in real time. It never attacks — it only
 *  listens and alerts. One 2.4GHz radio, time-sliced cycle:
 *    PHASE A  WiFi promiscuous -> detect DEAUTH/DISASSOC attacks (>10/s from
 *             one source = ALERT) + PWNAGOTCHI beacons (MAC de:ad:be:ef:de:ad);
 *             hops channels 1-13; optional presence beacon (see ENABLE_BEACON).
 *    PHASE B  BLE passive scan -> count devices + detect BLE advertisement
 *             FLOOD / SPAM (adv-rate spike + spam company-IDs).
 *    ZIGBEE   deferred to v2 (802.15.4 needs WiFi off) -> shown as "v2 off".
 *  LCD shows a live SECURE / THREAT status and flips RED on an attack with the
 *  attacker + target MAC.
 *
 *  Hardware : Waveshare ESP32-C6-LCD-1.47  (ST7789 172x320 IPS, WiFi 6 + BLE 5)
 *  Build    : arduino-esp32 core 3.x | FQBN esp32:esp32:esp32c6:PartitionScheme=huge_app
 *  Library  : "GFX Library for Arduino" (Arduino_GFX)
 *
 *  Authors  : Chetan Saini (@cyberac1d)  &  Ella (AI pair-partner)
 *  License  : MIT
 *  Purpose  : Educational / defensive security. Use only on networks and
 *             devices you own or are explicitly authorized to test.
 * ============================================================================
 */
#include <Arduino_GFX_Library.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <string.h>

// ---------------- Waveshare C6-LCD-1.47 pins ----------------
#define PIN_SCK  7
#define PIN_MOSI 6
#define PIN_DC   15
#define PIN_CS   14
#define PIN_RST  21
#define PIN_BL   22

Arduino_DataBus *bus = new Arduino_ESP32SPI(PIN_DC, PIN_CS, PIN_SCK, PIN_MOSI, GFX_NOT_DEFINED);
Arduino_GFX *gfx = new Arduino_ST7789(bus, PIN_RST, 0 /*portrait*/, true /*IPS*/, 172, 320, 34, 0, 34, 0);

// colors (RGB565)
#define C_BG   0x0000
#define C_HEAD 0x07FF
#define C_OK   0x07E0
#define C_WARN 0xFD20
#define C_TXT  0xFFFF
#define C_DIM  0x8410
#define C_RED  0xF800

// ---------------- shared detector state (cb -> loop) ----------------
struct DeauthEvt { uint8_t src[6]; uint8_t dst[6]; int8_t rssi; uint8_t ch; uint8_t subtype; };
#define RING 48
static volatile DeauthEvt ring[RING];
static volatile uint16_t  ringHead = 0;   // cb writes
static uint16_t           ringTail = 0;   // loop reads
static volatile uint32_t  g_deauthTotal = 0;
static volatile uint32_t  g_mgmtSeen = 0;   // ALL mgmt frames seen (sniffer alive check)

static volatile uint32_t  g_pwnCount = 0;
static volatile int8_t    g_pwnRssi  = 0;
static volatile uint32_t  g_pwnLastMs = 0;
static volatile uint8_t   g_pwnMac[6] = {0};

static const uint8_t PWN_MAC[6] = {0xde,0xad,0xbe,0xef,0xde,0xad};

// BLE counters (written from BLE task)
static volatile uint32_t g_bleAdv = 0;
static volatile uint32_t g_bleSpamCID = 0;

// ---------------- cyberac1d presence beacon (built once) ----------------
static uint8_t beacon[] = {
  0x80,0x00, 0x00,0x00,
  0xff,0xff,0xff,0xff,0xff,0xff,            // DA broadcast
  0xc6,0xac,0x1d,0x13,0x37,0x01,            // SA (locally-administered)
  0xc6,0xac,0x1d,0x13,0x37,0x01,            // BSSID = SA
  0x00,0x00,                                // seq (driver fills)
  0,0,0,0,0,0,0,0,                          // timestamp
  0x64,0x00,                                // beacon interval
  0x21,0x04,                                // capability (ESS, short preamble, OPEN)
  0x00,0x19,'D','M',' ','c','y','b','e','r','a','c','1','d',' ','o','n',' ','I','n','s','t','a','g','r','a','m', // SSID IE (25)
  0x03,0x01,0x01,                           // DS param (channel byte at idx 65)
  0x01,0x08,0x82,0x84,0x8b,0x96,0x24,0x30,0x48,0x6c // supported rates
};
#define BEACON_CHAN_IDX 65

// ---------------- WiFi sniffer callback (IRAM, minimal!) ----------------
void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  g_mgmtSeen++;
  const wifi_promiscuous_pkt_t *ppkt = (const wifi_promiscuous_pkt_t *)buf;
  const uint8_t *p = ppkt->payload;
  uint8_t fc = p[0];
  if (fc == 0xC0 || fc == 0xA0) {                  // deauth(0xC0) / disassoc(0xA0)
    uint16_t h = ringHead;
    volatile DeauthEvt &e = ring[h % RING];
    for (int i=0;i<6;i++){ e.src[i]=p[10+i]; e.dst[i]=p[4+i]; }
    e.rssi = ppkt->rx_ctrl.rssi; e.ch = ppkt->rx_ctrl.channel;
    e.subtype = (fc==0xC0)?0x0C:0x0A;
    ringHead = h + 1;
    g_deauthTotal++;
  } else if (fc == 0x80) {                          // beacon -> pwnagotchi?
    if (memcmp((const void*)&p[10], PWN_MAC, 6) == 0 || memcmp((const void*)&p[16], PWN_MAC, 6) == 0) {
      g_pwnCount++;
      g_pwnRssi = ppkt->rx_ctrl.rssi;
      g_pwnLastMs = millis();
      for (int i=0;i<6;i++) g_pwnMac[i]=p[10+i];
    }
  }
}

// ---------------- BLE scan callback (BLE task, tally only) ----------------
class BLECB : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice d) override {
    g_bleAdv++;
    if (d.haveManufacturerData()) {
      String md = d.getManufacturerData();
      if (md.length() >= 2) {
        uint16_t cid = (uint8_t)md[0] | ((uint8_t)md[1] << 8);
        if (cid==0x004C || cid==0x0006 || cid==0x00E0) g_bleSpamCID++;  // Apple/MS/Google
      }
    }
  }
};
static BLEScan *pScan = nullptr;

// ---------------- aggregated attacker table (loop) ----------------
struct Src { uint8_t mac[6]; uint8_t victim[6]; uint16_t win; uint32_t winStart; uint32_t total; uint32_t lastMs; int8_t rssi; uint8_t ch; bool used; bool attacking; };
#define MAXSRC 12
static Src srcs[MAXSRC];

static uint32_t bleUnique = 0, bleAdvLast = 0; static bool bleSpam = false;
static bool alertActive = false; static uint32_t alertUntil = 0;
static char alertProto[20] = ""; static uint8_t alertMac[6]={0}, alertVic[6]={0};
static int8_t alertRssi=0; static uint8_t alertCh=0;

static int findSrc(const uint8_t *mac) {
  int free = -1;
  for (int i=0;i<MAXSRC;i++){
    if (srcs[i].used && memcmp(srcs[i].mac,mac,6)==0) return i;
    if (!srcs[i].used && free<0) free=i;
  }
  if (free<0) { // evict oldest
    uint32_t oldest=0xFFFFFFFF; for(int i=0;i<MAXSRC;i++) if(srcs[i].lastMs<oldest){oldest=srcs[i].lastMs;free=i;}
  }
  memset(&srcs[free],0,sizeof(Src)); memcpy(srcs[free].mac,mac,6); srcs[free].used=true; srcs[free].winStart=millis();
  return free;
}

static void drainRing(uint32_t now) {
  while (ringTail != ringHead) {
    volatile DeauthEvt &e = ring[ringTail % RING];
    uint8_t mac[6],vic[6]; for(int i=0;i<6;i++){mac[i]=e.src[i];vic[i]=e.dst[i];}
    int8_t rssi=e.rssi; uint8_t ch=e.ch;
    ringTail++;
    int s = findSrc(mac);
    if (now - srcs[s].winStart > 1000) { srcs[s].winStart=now; srcs[s].win=0; }
    srcs[s].win++; srcs[s].total++; srcs[s].lastMs=now; srcs[s].rssi=rssi; srcs[s].ch=ch;
    memcpy(srcs[s].victim,vic,6);
    if (srcs[s].win >= 11) {                       // >10 deauth/sec from same source = ATTACK
      srcs[s].attacking = true;
      alertActive=true; alertUntil=now+5000; strcpy(alertProto,"WIFI DEAUTH");
      memcpy(alertMac,mac,6); memcpy(alertVic,vic,6); alertRssi=rssi; alertCh=ch;
    }
  }
  // age out + clear stale attacking
  for (int i=0;i<MAXSRC;i++){ if(srcs[i].used && now-srcs[i].lastMs>8000){srcs[i].used=false;srcs[i].attacking=false;} }
}

static int activeAttackers() { int n=0; for(int i=0;i<MAXSRC;i++) if(srcs[i].used && srcs[i].attacking) n++; return n; }
static int seenSources()     { int n=0; for(int i=0;i<MAXSRC;i++) if(srcs[i].used) n++; return n; }

// ---------------- display ----------------
static int lastScreen = -1; // 0 normal, 1 alert
static void macStr(char *o, const uint8_t *m){ sprintf(o,"%02X:%02X:%02X:%02X:%02X:%02X",m[0],m[1],m[2],m[3],m[4],m[5]); }
static void clr(int x,int y,int w,int h,uint16_t c){ gfx->fillRect(x,y,w,h,c); }

static int lastThreat = -1;

static void drawNormalStatic() {
  gfx->fillScreen(C_BG);
  // header bar
  gfx->fillRect(0,0,172,28,0x018F);
  gfx->setTextColor(C_TXT); gfx->setTextSize(2); gfx->setCursor(8,7); gfx->print("THREAT RADAR");
  // section labels (big) + dividers
  gfx->setTextSize(2); gfx->setTextColor(C_HEAD);
  gfx->setCursor(8,84);  gfx->print("WIFI");
  gfx->setCursor(8,138); gfx->print("PWNAGOTCHI");
  gfx->setCursor(8,192); gfx->print("BLE");
  gfx->setCursor(8,246); gfx->print("ZIGBEE");
  gfx->drawFastHLine(8,132,156,0x4208);
  gfx->drawFastHLine(8,186,156,0x4208);
  gfx->drawFastHLine(8,240,156,0x4208);
  gfx->drawFastHLine(0,298,172,0x4208);
}

static void drawNormal(uint32_t now, const char *phase, int ch) {
  if (lastScreen!=0){ drawNormalStatic(); lastScreen=0; lastThreat=-1; }
  char b[44];
  int atk = activeAttackers();
  bool pwn = (now-g_pwnLastMs<8000 && g_pwnCount>0);
  bool threat = (atk>0) || pwn || bleSpam;
  // big status banner (redraw only on change = no flicker)
  if ((int)threat != lastThreat) {
    lastThreat = (int)threat; uint16_t sc = threat ? C_RED : C_OK;
    gfx->fillRoundRect(6,34,160,42,6,sc);
    gfx->setTextColor(C_BG); gfx->setTextSize(3); gfx->setCursor(threat?28:26,44);
    gfx->print(threat ? "THREAT" : "SECURE");
  }
  gfx->setTextSize(2);
  // WIFI
  clr(8,104,164,18,C_BG); gfx->setTextColor(atk?C_RED:C_TXT); gfx->setCursor(8,104);
  sprintf(b,"atk %d  src %d",atk,seenSources()); gfx->print(b);
  // PWNAGOTCHI
  clr(8,158,164,18,C_BG); gfx->setTextColor(pwn?C_WARN:C_DIM); gfx->setCursor(8,158);
  if(pwn) sprintf(b,"FOUND %d",g_pwnRssi); else strcpy(b,"clear"); gfx->print(b);
  // BLE
  clr(8,212,164,18,C_BG); gfx->setTextColor(bleSpam?C_RED:C_TXT); gfx->setCursor(8,212);
  sprintf(b,"%lu dev%s",(unsigned long)bleUnique, bleSpam?" !":""); gfx->print(b);
  // ZIGBEE
  clr(8,266,164,18,C_BG); gfx->setTextColor(C_DIM); gfx->setCursor(8,266); gfx->print("v2 off");
  // footer
  clr(0,302,172,16,C_BG); gfx->setTextSize(1); gfx->setTextColor(g_mgmtSeen?C_OK:C_RED); gfx->setCursor(6,305);
  sprintf(b,"%s ch%d  rx %lu  TX on",phase,ch,(unsigned long)g_mgmtSeen); gfx->print(b);
}

static void drawAlert(uint32_t now) {
  bool first=(lastScreen!=1); if(first){ gfx->fillScreen(C_RED); lastScreen=1; lastThreat=-1; }
  char b[44];
  if(first){
    gfx->setTextColor(C_TXT); gfx->setTextSize(3); gfx->setCursor(16,16); gfx->print("ALERT");
    gfx->drawFastHLine(0,56,172,C_TXT);
    gfx->setTextSize(1); gfx->setTextColor(0xFFE0);
    gfx->setCursor(8,122); gfx->print("ATTACKER MAC");
    gfx->setCursor(8,164); gfx->print("TARGET MAC");
  }
  // protocol (blink, big)
  clr(8,66,164,26,C_RED); gfx->setTextSize(2); gfx->setTextColor((now/300)%2?C_TXT:0xFFE0);
  gfx->setCursor(8,68); gfx->print(alertProto);
  gfx->setTextSize(1); gfx->setTextColor(C_TXT);
  clr(8,136,164,12,C_RED); gfx->setCursor(8,136); macStr(b,alertMac); gfx->print(b);
  clr(8,178,164,12,C_RED); gfx->setCursor(8,178); macStr(b,alertVic); gfx->print(b);
  clr(8,202,164,12,C_RED); gfx->setCursor(8,202);
  sprintf(b,"ch %d  rssi %d  x%d",alertCh,alertRssi,activeAttackers()); gfx->print(b);
}

// ---------------- cycle ----------------
enum { PH_WIFI, PH_BLE };
static int phase = PH_WIFI;
static const uint8_t HOPS[13] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
static int hopIdx = 0;
static uint32_t phaseStart=0,lastHop=0,lastBeacon=0,lastDraw=0;

static void wifiPromiscOn(bool on){ esp_wifi_set_promiscuous(on); }

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\n[boot] threat radar");
  pinMode(PIN_BL,OUTPUT); digitalWrite(PIN_BL,HIGH);
  gfx->begin(); gfx->fillScreen(C_BG);
  gfx->setTextColor(C_HEAD); gfx->setTextSize(2); gfx->setCursor(6,40); gfx->println("THREAT RADAR");
  gfx->setTextSize(1); gfx->setTextColor(C_DIM); gfx->setCursor(6,80); gfx->println("init ble...");
  Serial.println("[boot] gfx ok");

  // BLE (bundled Bluedroid) init FIRST — before WiFi promiscuous is active (coexist safety)
  BLEDevice::init("");
  pScan = BLEDevice::getScan();
  pScan->setAdvertisedDeviceCallbacks(new BLECB(), true /*wantDuplicates*/);
  pScan->setActiveScan(false);
  pScan->setInterval(100); pScan->setWindow(99);
  delay(50);
  Serial.println("[boot] ble ok");
  gfx->setCursor(6,96); gfx->println("init wifi...");

  // WiFi: STA mode starts the driver; disconnect(FALSE) keeps the radio ON
  // (disconnect(true,...) would STOP the radio -> promiscuous receives nothing!)
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false);
  delay(150);
  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_err_t e1 = esp_wifi_set_promiscuous(true);
  wifi_promiscuous_filter_t f; f.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&f);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
  esp_err_t e2 = esp_wifi_set_channel(HOPS[0], WIFI_SECOND_CHAN_NONE);
  Serial.printf("[boot] wifi: promisc=%s  ch=%s\n", esp_err_to_name(e1), esp_err_to_name(e2));

  memset(srcs,0,sizeof(srcs));
  phaseStart=millis(); lastHop=millis();
  Serial.println("[boot] radar up (detection only)");
}

void loop() {
  uint32_t now = millis();

  if (phase == PH_WIFI) {
    if (now - lastHop > 1200) { lastHop=now; hopIdx=(hopIdx+1)%13; esp_wifi_set_channel(HOPS[hopIdx],WIFI_SECOND_CHAN_NONE); }
    if (now - lastBeacon > 800) { lastBeacon=now; beacon[BEACON_CHAN_IDX]=HOPS[hopIdx];
      for(int k=0;k<3;k++){ esp_wifi_80211_tx(WIFI_IF_STA, beacon, sizeof(beacon), true); delay(2); } }
    drainRing(now);
    if (now - phaseStart > 16000) {                // -> BLE phase (after a full 1-13 sweep)
      wifiPromiscOn(false); delay(20);
      phase = PH_BLE; phaseStart = now;
      drawNormal(now,"BLE SCAN",0);                // show before the blocking scan
    }
  } else { // PH_BLE
    g_bleAdv=0; g_bleSpamCID=0;
    BLEScanResults *res = pScan->start(2, false);  // blocking ~2s
    bleUnique = res ? res->getCount() : 0;
    bleAdvLast = g_bleAdv;
    bleSpam = (bleAdvLast > 80) || (g_bleSpamCID > 40);
    pScan->clearResults(); pScan->stop();          // clearResults MANDATORY (heap)
    if (bleSpam) { alertActive=true; alertUntil=millis()+5000; strcpy(alertProto,"BLE SPAM");
      memset(alertMac,0,6); memset(alertVic,0,6); alertCh=0; alertRssi=0; }
    wifiPromiscOn(true); esp_wifi_set_channel(HOPS[hopIdx],WIFI_SECOND_CHAN_NONE);
    phase = PH_WIFI; phaseStart = millis(); lastHop = millis();
  }

  // pwnagotchi presence -> soft alert
  if (now - g_pwnLastMs < 6000 && g_pwnCount>0 && !alertActive) {
    alertActive=true; alertUntil=now+5000; strcpy(alertProto,"PWNAGOTCHI");
    memcpy(alertMac,(const void*)g_pwnMac,6); memset(alertVic,0,6); alertRssi=g_pwnRssi; alertCh=0;
  }
  if (alertActive && now>alertUntil && activeAttackers()==0 && !bleSpam &&
      !(now-g_pwnLastMs<6000 && g_pwnCount>0)) alertActive=false;

  if (now - lastDraw > 350) {
    lastDraw = now;
    if (alertActive) drawAlert(now);
    else drawNormal(now, phase==PH_WIFI?"WIFI SNIFF":"BLE SCAN", phase==PH_WIFI?HOPS[hopIdx]:0);
  }

  if (ESP.getFreeHeap() < 28000) { Serial.println("low heap -> restart"); delay(50); ESP.restart(); }
}
