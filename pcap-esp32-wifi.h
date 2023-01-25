/*
 * pcap-esp32-wifi.c: Packet capture interface for the built-in WiFi
 * interface on ESP32-based platforms.
 *
 * Author: Glen Cornell (glen.m.cornell@gmail.com)
 */

pcap_t *esp32_wifi_create(const char *, char *, int *);
int esp32_wifi_findalldevs(pcap_if_list_t *devlistp, char *errbuf);
