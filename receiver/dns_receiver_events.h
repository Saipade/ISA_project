#ifndef ISA22_DNS_RECEIVER_EVENTS_H
#define ISA22_DNS_RECEIVER_EVENTS_H

#include <netinet/in.h>

/**
 * Tato metoda je volána serverem (příjemcem) při přijetí zakódovaných dat od klienta (odesílatele).
 * V případě použití více doménových jmen pro zakódování dat, volejte funkci pro každé z nich.
 *
 * @param file_path Cesta k cílovému souboru
 * @param encoded_data Zakódovaná data do doménového jména (např.: "acfe2a42b.example.com")
 */
void dns_receiver__on_query_parsed(char *file_path, char *encoded_data);

/**
 * Tato metoda je volána serverem (příjemcem) při příjmu části dat od klienta (odesílatele).
 *
 * @param source IPv4 adresa odesílatele
 * @param file_path Cesta k cílovému souboru
 * @param chunk_id Identifikátor části dat
 * @param chunk_size Velikost části dat v bytech
 */
void dns_receiver__on_chunk_received(struct in_addr *source, char *file_path, int chunk_id, int chunk_size);

/**
 * Tato metoda je volána serverem (příjemcem) při příjmu části dat od klienta (odesílatele).
 *
 * @param source IPv6 adresa odesílatele
 * @param file_path Cesta k cílovému souboru
 * @param chunk_id Identifikátor části dat
 * @param chunk_size Velikost části dat v bytech
 */
void dns_receiver__on_chunk_received6(struct in6_addr *source, char *file_path, int chunk_id, int chunk_size);

/**
 * Tato metoda je volána serverem (příjemcem) při zahájení přenosu od klienta (odesílatele).
 *
 * @param source IPv4 adresa odesílatele
 */
void dns_receiver__on_transfer_init(struct in_addr *source);

/**
 * Tato metoda je volána serverem (příjemcem) při zahájení přenosu od klienta (odesílatele).
 *
 * @param source IPv6 adresa odesílatele
 */
void dns_receiver__on_transfer_init6(struct in6_addr *source);

/**
 * Tato metoda je volána serverem (příjemcem) při dokončení přenosu jednoho souboru od klienta (odesílatele).
 *
 * @param file_path Cesta k cílovému souboru
 * @param file_size Celková velikost přijatého souboru v bytech
 */
void dns_receiver__on_transfer_completed(char *file_path, int file_size);

#endif //ISA22_DNS_RECEIVER_EVENTS_H