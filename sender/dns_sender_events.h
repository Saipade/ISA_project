#ifndef ISA22_DNS_SENDER_EVENTS_H
#define ISA22_DNS_SENDER_EVENTS_H

#include <netinet/in.h>

/**
 * Tato metoda je volána klientem (odesílatelem) při zakódování části dat do doménového jména.
 * V případě použití více doménových jmen pro zakódování dat, volejte funkci pro každé z nich.
 *
 * @param file_path Cesta k cílovému souboru
 * @param chunk_id Identifikátor části dat
 * @param encoded_data Zakódovaná data do doménového jména (např.: "acfe2a42b.example.com")
 */
void dns_sender__on_chunk_encoded(char *file_path, int chunk_id, char *encoded_data);

/**
 * Tato metoda je volána klientem (odesílatelem) při odeslání části dat serveru (příjemci).
 *
 * @param dest IPv4 adresa příjemce
 * @param file_path Cesta k cílovému souboru (relativní na straně příjemce)
 * @param chunk_id Identifikátor části dat
 * @param chunk_size Velikost části dat v bytech
 */
void dns_sender__on_chunk_sent(struct in_addr *dest, char *file_path, int chunk_id, int chunk_size);

/**
 * Tato metoda je volána klientem (odesílatelem) při odeslání části dat serveru (příjemci).
 *
 * @param dest IPv6 adresa příjemce
 * @param file_path Cesta k cílovému souboru (relativní na straně příjemce)
 * @param chunk_id Identifikátor části dat
 * @param chunk_size Velikost části dat v bytech
 */
void dns_sender__on_chunk_sent6(struct in6_addr *dest, char *file_path, int chunk_id, int chunk_size);

/**
 * Tato metoda je volána klientem (odesílatelem) při zahájení přenosu serveru (příjemci).
 *
 * @param dest IPv4 adresa příjemce
 */
void dns_sender__on_transfer_init(struct in_addr *dest);

/**
 * Tato metoda je volána klientem (odesílatelem) při zahájení přenosu serveru (příjemci).
 *
 * @param dest IPv6 adresa příjemce
 */
void dns_sender__on_transfer_init6(struct in6_addr *dest);

/**
 * Tato metoda je volána klientem (odesílatelem) při dokončení přenosu jednoho souboru serveru (příjemci).
 *
 * @param file_path Cesta k cílovému souboru
 * @param file_size Celková velikost přijatého souboru v bytech
 */
void dns_sender__on_transfer_completed(char *file_path, int file_size);

#endif //ISA22_DNS_SENDER_EVENTS_H