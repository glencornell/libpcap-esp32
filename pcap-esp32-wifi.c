//
// pcap-esp32-wifi.c: Packet capture interface for ESP32 WiFi device.
//
// Authors: Glen Cornell (glen.m.cornell@gmail.com)
//
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdint.h>
#include <esp_wifi.h>
#include <esp_err.h>
#include <freertos/stream_buffer.h>
#include <pcap/radiotap.h>
#include <endian.h>

#include "pcap-int.h"
#include "pcap-esp32-wifi.h"

// Bitmask of fields present in the radiotap header for received wifi
// packets on the ESP32 platform.
#define ESP32_WIFI_RX_RADIOTAP_PRESENT      \
  ((1 << IEEE80211_RADIOTAP_FLAGS) |        \
   (1 << IEEE80211_RADIOTAP_CHANNEL) |      \
   (1 << IEEE80211_RADIOTAP_RATE) |         \
   (1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL) | \
   0)

// The radiotap header for received packets on the ESP32 platform.
// The order of the fields is important.  They must appear in the
// order as defined in ESP32_WIFI_RX_RADIOTAP_PRESENT.
struct rx_radiotap_hdr {
  struct ieee80211_radiotap_header hdr;
  uint8_t flags;
  uint8_t rate;
  uint16_t chan_freq;
  uint16_t chan_flags;
  int8_t antsignal;
} __packed;


static int esp32_wifi_activate(pcap_t *p);
static int esp32_wifi_can_set_rfmon(pcap_t *p);
static int esp32_wifi_get_channel(pcap_t *p, uint8_t *channel);
static int esp32_wifi_getnonblock(pcap_t *p);
static int esp32_wifi_inject(pcap_t *, const void *, int);
static int esp32_wifi_read(pcap_t *pcap, int cnt, pcap_handler callback, u_char *user);
static int esp32_wifi_set_channel(pcap_t *p, uint8_t channel);
static int esp32_wifi_setnonblock(pcap_t *p, int nonblock);
static int esp32_wifi_stats(pcap_t *p, struct pcap_stat *ps _U_);
static uint16_t esp32_channel_to_radiotap(uint8_t channel);
static uint8_t esp32_rate_to_radiotap(uint8_t rate);
static void esp32_to_radiotap(wifi_pkt_rx_ctrl_t const *in, struct rx_radiotap_hdr *out);
static void esp32_wifi_breakloop(pcap_t *p);
static void esp32_wifi_rx_pkt_cb(void* buf, wifi_promiscuous_pkt_type_t type);
static void esp32_wifi_rx_pkt_cb(void* buf, wifi_promiscuous_pkt_type_t type);

// There is only one WiFi interface on the ESP32. That's good because
// there is no user defined parameter in the ESP32 promiscuous mode
// callback.  So there's no way to associate the pcap record with the
// callback.

// Allocate memory for the message buffer
#define STORAGE_SIZE_BYTES 4096

// Defines the message buffer memory
static uint8_t esp32_stream_buffer_storage[ STORAGE_SIZE_BYTES ];

// The stream buffer structure
static StaticStreamBuffer_t esp32_stream_buffer_priv;

// The handle to the stream buffer
static StreamBufferHandle_t esp32_stream_buffer;

// ESP32-sepcific pcap device state information
struct pcap_esp32 {
  pcap_t * orig;
};

static int esp32_wifi_set_channel(pcap_t *p, uint8_t channel)
{
  int status = 0;
  struct pcap_esp32 *pe = p->priv;
  esp_err_t err = ESP_OK;
  char errbuf[PCAP_ERRBUF_SIZE];

  err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  if (err != ESP_OK) {
    snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
             "esp_wifi_set_channel:(%d) %s: %s",
             err,
             p->opt.device,
             esp_err_to_name_r(err, errbuf, sizeof(errbuf)));
    status = PCAP_ERROR;
  }
  return status;
}

static int esp32_wifi_get_channel(pcap_t *p, uint8_t *channel)
{
  int status = 0;
  struct pcap_esp32 *pe = p->priv;
  esp_err_t err = ESP_OK;
  char errbuf[PCAP_ERRBUF_SIZE];
  wifi_second_chan_t second;

  err = esp_wifi_get_channel(channel, &second);
  if (err != ESP_OK) {
    snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
             "esp_wifi_get_channel:(%d) %s: %s",
             err,
             p->opt.device,
             esp_err_to_name_r(err, errbuf, sizeof(errbuf)));
    status = PCAP_ERROR;
  }
  return status;
}

static int esp32_wifi_can_set_rfmon(pcap_t *p)
{
  return true;
}

static int esp32_wifi_getnonblock(pcap_t *p)
{
  snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "Non-blocking mode not supported on esp32 devices");
  return PCAP_ERROR;
}

static int esp32_wifi_setnonblock(pcap_t *p, int nonblock _U_)
{
  snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "Non-blocking mode not supported on esp32 devices");
  return PCAP_ERROR;
}

static int esp32_wifi_stats(pcap_t *p, struct pcap_stat *ps _U_)
{
  snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "Stats not supported on esp32 devices");
  return PCAP_ERROR;
}

static void esp32_wifi_breakloop(pcap_t *p)
{
  esp_wifi_stop();

  // TODO: do we need this?
  esp_wifi_set_promiscuous(false);

  pcap_breakloop_common(p);
}


static uint16_t esp32_channel_to_radiotap(uint8_t channel) {
  static const uint16_t freq_list[] = {
    2412, 2417, 2422, 2427, 2432, 2437, 2442,
    2447, 2452, 2457, 2462, 2467, 2472, 2484
  };
#define FREQ_COUNT ARRAY_SIZE(freq_list)
  
  return freq_list[channel - 1];
}

static uint8_t esp32_rate_to_radiotap(uint8_t rate) {
  // TODO: this probably needs to be converted to
  // IEEE80211_RADIOTAP_RATE units (500 Kb/s).
  return rate;
}

// translate the ESP32 WiFi metadata header to a radiotap header that
// libraries like wireshark and tcpdump can understand.  This has
// useful information like RSSI and the primary channel that the
// packet was received on.
static void esp32_to_radiotap(wifi_pkt_rx_ctrl_t const *in,
                              struct rx_radiotap_hdr *radiotap_hdr)
{
  memset(radiotap_hdr, 0, sizeof(struct rx_radiotap_hdr));
  
  radiotap_hdr->hdr.it_version = PKTHDR_RADIOTAP_VERSION;
  radiotap_hdr->hdr.it_pad = 0;
  radiotap_hdr->hdr.it_len = htole16 (sizeof(struct rx_radiotap_hdr));
  radiotap_hdr->hdr.it_present = htole32 (ESP32_WIFI_RX_RADIOTAP_PRESENT);

  radiotap_hdr->flags = 0;
  radiotap_hdr->chan_flags = htole16(IEEE80211_CHAN_2GHZ);
  radiotap_hdr->chan_freq = htole16(esp32_channel_to_radiotap(in->channel));
  radiotap_hdr->rate = esp32_rate_to_radiotap(in->rate);
  radiotap_hdr->antsignal = in->rssi;
}

// This callback is invoked when a packet is read on the
// interface. Note that this callback is not invoked in the
// application's thread context, which is why this callback places the
// inbound packet in a FreeRTOS StremBuffer. So be careful how you use
// global variables.
static void esp32_wifi_rx_pkt_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  // Construct a pcap packet and then send it to a FreeRTOS stream
  // buffer.  Stream buffers were chosen because 1. the calback is
  // invoked from the wifi task, not the application task context,
  // 2. the pcap format is streamable and 3. reduce the need to use a
  // temporary buffer to construct a pcap packet.
  wifi_promiscuous_pkt_t *esp32_pkt = (wifi_promiscuous_pkt_t*)buf;
  switch(type) {
  case WIFI_PKT_MGMT:
  case WIFI_PKT_CTRL:
  case WIFI_PKT_DATA:
    {
      struct pcap_pkthdr pcap_hdr;
      struct rx_radiotap_hdr rt_hdr;
      struct timeval timestamp = { 0, esp32_pkt->rx_ctrl.timestamp };
      const struct timeval zero = { 0, 0 };
      size_t nwritten;

      // construct the radiotap header
      esp32_to_radiotap(&esp32_pkt->rx_ctrl, &rt_hdr);

      // construct & send the pcap packet header
      timeradd(&zero, &timestamp, &pcap_hdr.ts);
      pcap_hdr.len = pcap_hdr.caplen = esp32_pkt->rx_ctrl.sig_len + sizeof(rt_hdr);
      nwritten = xStreamBufferSend(esp32_stream_buffer,
                                   (void *) &pcap_hdr,
                                   sizeof(pcap_hdr),
                                   // TODO: maybe use the following instead:
                                   //pdMS_TO_TICKS(pcap->opt.timeout));
                                   0);
      if (nwritten != sizeof(pcap_hdr)) {
        // TODO: what to do?
      }

      // send the radiotap header
      nwritten = xStreamBufferSend(esp32_stream_buffer,
                                   (void *) &rt_hdr,
                                   sizeof(rt_hdr),
                                   // TODO: maybe use the following instead:
                                   //pdMS_TO_TICKS(pcap->opt.timeout));
                                   0);
      if (nwritten != sizeof(rt_hdr)) {
        // TODO: what to do?
      }

      // Send the packet
      nwritten = xStreamBufferSend(esp32_stream_buffer,
                                   (void *) esp32_pkt->payload,
                                   esp32_pkt->rx_ctrl.sig_len,
                                   // TODO: maybe use the following instead:
                                   //pdMS_TO_TICKS(pcap->opt.timeout));
                                   0);
      if (nwritten != esp32_pkt->rx_ctrl.sig_len) {
        // TODO: what to do?
      }
    }
    break;
  case WIFI_PKT_MISC:
    /**< Other type, such as MIMO etc. 'buf' argument is wifi_promiscuous_pkt_t but the payload is zero length. */
    break;
  }
};

// read all of the messages in the message queue and invoke the
// callback on each.
static int esp32_wifi_read(pcap_t *pcap, int cnt, pcap_handler callback, u_char *user)
{
  int status = 0;
  size_t nread;
  struct pcap_pkthdr pcap_hdr;

  while(xStreamBufferBytesAvailable(esp32_stream_buffer) > 0) {
    // first read the pcap packet header:
    //TODO: move this to something like readn() from Richard Stevens unix network programming
    nread = xStreamBufferReceive(esp32_stream_buffer,
                                 (void*)&pcap_hdr,
                                 sizeof(pcap_hdr),
                                 pdMS_TO_TICKS(pcap->opt.timeout));
    if (nread != sizeof(pcap_hdr)) {
      // TODO: what to do? I don't think that we can recover from this
      snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
               "esp32_wifi_read: xStreamBufferRead of pcap header");
      status = PCAP_ERROR;
      break;
    }

    {
      // allocate space on the stack for a complete pcap packet
      uint8_t buf[pcap_hdr.caplen];

      // Now read the packet into the buffer
      //TODO: move this to something like readn() from Richard Stevens unix network programming
      nread = xStreamBufferReceive(esp32_stream_buffer,
                                   (void*)buf,
                                   pcap_hdr.caplen,
                                   pdMS_TO_TICKS(pcap->opt.timeout));
      if (nread != pcap_hdr.caplen) {
        // TODO: what to do? I don't think that we can recover from this
        snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
                 "esp32_wifi_read: xStreamBufferRead of pcap payload");
        status = PCAP_ERROR;
        break;
      }
      // invoke the user's callback
      callback(user, &pcap_hdr, buf);
    }
  }
  return status;
}

static int esp32_wifi_inject(pcap_t *p, const void *buf, int size)
{
  int status = 0;
  // TODO: send the message
#warning not implemented
  return status;
}

#define PCAP_ESP32_WIFI_ERROR_CHECK(x,msg) do {                    \
    esp_err_t err = (x);                                           \
    char errbuf[PCAP_ERRBUF_SIZE];                                 \
    if (err != ESP_OK) {                                           \
      snprintf(p->errbuf, PCAP_ERRBUF_SIZE,                        \
               msg ":(%d) %s: %s",                                 \
               err,                                                \
               p->opt.device,                                      \
               esp_err_to_name_r(err, errbuf, sizeof(errbuf)));    \
      status = PCAP_ERROR;                                         \
      return status;                                               \
    }                                                              \
  } while (0);


static int esp32_wifi_activate(pcap_t *p)
{
  int status = 0;
  struct pcap_esp32 *pe = p->priv;
  const wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  const uint8_t channel = 1;

  // TODO: should this be WIFI_PROMIS_FILTER_MASK_ALL to get all
  // packets and let libpcap and higher level applications filter?
  const wifi_promiscuous_filter_t filter =
    {
     .filter_mask = 0
     | WIFI_PROMIS_FILTER_MASK_MGMT
     | WIFI_PROMIS_FILTER_MASK_DATA
    };

  // The main task calls esp_wifi_init() to create the Wi-Fi driver
  // task and initialize the Wi-Fi driver.
  PCAP_ESP32_WIFI_ERROR_CHECK(esp_wifi_init(&cfg), "esp_wifi_init");
  PCAP_ESP32_WIFI_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM), "esp_wifi_set_storage");
  PCAP_ESP32_WIFI_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL), "esp_wifi_set_mode");
  PCAP_ESP32_WIFI_ERROR_CHECK(esp_wifi_start(), "esp_wifi_start");

  if (p->opt.rfmon) {
    // set promiscuous mode (actually, it's RFMON mode)
    PCAP_ESP32_WIFI_ERROR_CHECK(esp_wifi_set_promiscuous(true), "esp_wifi_set_promiscuous");

    // set the packet filter
    PCAP_ESP32_WIFI_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter), "esp_wifi_set_promiscuous_filter");

    // Set the sniffing callback
    PCAP_ESP32_WIFI_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&esp32_wifi_rx_pkt_cb), "esp_wifi_set_promiscuous_rx_cb");
  }

  // Set the channel
  esp32_wifi_set_channel(p, channel);

  return status;
}

pcap_t *eps32_create(const char *device, char *ebuf, int *is_ours)
{
  const char *cp;
  char *cpend;
  long devnum;
  pcap_t *p;
  long stream = 0;

  // Does this look like a ESP32 device?
  cp = strrchr(device, '/');
  if (cp == NULL)
    cp = device;
  // Does it begin with "esp32-wlan"?
  if (strncmp(cp, "esp32-wlan", 10) != 0) {
    // Nope
    *is_ours = 0;
    return NULL;
  }
  // There is only one wifi device on the esp32.  If the ESP32 in the
  // future ever supports more than one, then check for unique
  // instance number (i.e. "esp32-wlan[0-9]+")
  *is_ours = 1;

  p = PCAP_CREATE_COMMON(ebuf, struct pcap_esp32);
  if (p == NULL)
    return NULL;

  // "select()" and "poll()" don't work for the esp32 wifi because it
  // does not use a file descriptor interface. Rather, a callback is
  // called when a new packet is read.
  p->selectable_fd    = -1;
   // TODO: also support DLT_IEEE802_11 (which has no radiotap header
  p->linktype         = DLT_IEEE802_11_RADIO;

  // ESP32 specific functions
  p->read_op          = esp32_wifi_read;
  p->activate_op      = esp32_wifi_activate;
  p->can_set_rfmon_op = esp32_wifi_can_set_rfmon;
  p->inject_op        = esp32_wifi_inject;
  // BPF is not supported on ESP32
  //  p->setfilter_op     = install_bpf_program;  // No kernel filtering
  p->setdirection_op  = NULL;                     // Not supported
  p->set_datalink_op  = NULL;                     // Can't change data link type
  p->getnonblock_op   = esp32_wifi_getnonblock;   // Not supported
  p->setnonblock_op   = esp32_wifi_setnonblock;   // Not supported
  p->stats_op         = esp32_wifi_stats;         // Not supported
  p->breakloop_op     = esp32_wifi_breakloop;
  p->set_channel_op   = esp32_wifi_set_channel;
  p->get_channel_op   = esp32_wifi_get_channel;

  // I have no idea what the ESP32 timer is capable of, but let's say
  // that it supports microsecond and nanosecond time stamps until
  // someone proves me wrong.
  p->tstamp_precision_list = malloc(2 * sizeof(u_int));
  if (p->tstamp_precision_list == NULL) {
    pcap_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
                              errno, "malloc");
    pcap_close(p);
    return NULL;
  }
  p->tstamp_precision_list[0] = PCAP_TSTAMP_PRECISION_MICRO;
  p->tstamp_precision_list[1] = PCAP_TSTAMP_PRECISION_NANO;
  p->tstamp_precision_count = 2;

  // Create the stream buffer linking the wifi task and this
  // application task context:
  esp32_stream_buffer = xStreamBufferCreateStatic
    (sizeof(esp32_stream_buffer_storage),
     1, // number of bytes in stream to unblock reading task
     esp32_stream_buffer_storage,
     &esp32_stream_buffer_priv);

  return p;
}

// Add all ESP32 WiFi devices.
int eps32_findalldevs(pcap_if_list_t *devlistp, char *errbuf)
{
  // There is only one WiFi defvice on the ESP32
  if (add_dev(devlistp, "esp32-wlan0", 0, "ESP32 IEEE 802.11 b/g/n (802.11n up to 150 Mbps), 2.4 GHz", errbuf) == NULL) {
    // Failure.
    return (-1);
  }
  return (0);
}
