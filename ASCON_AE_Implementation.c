#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
typedef unsigned long long uint64_t;

#define ROTR(x, i) (x >> i) ^(x << (64 - i))

int loopNumber = 12; 

uint64_t c[16] = {0x000000000000003c,0x000000000000002d,0x000000000000001e,0x000000000000000f,0x00000000000000f0,0x00000000000000e1,0x00000000000000d2,0x00000000000000c3};
void print_state(uint64_t x[5]){
    for(int i = 0; i < 5; i++){
        printf("%016llx\n", x[i]);
        //printf("%016x\n", x[i]);
    }
    printf("\n");
}
void p(uint64_t x[5], int i, int rnd){
    x[2] ^= c[16 - rnd + i];

    uint64_t t[5] = {0};
    x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1];
	t[0] = x[0]; t[1] = x[1]; t[2] = x[2]; t[3] = x[3]; t[4] = x[4];
	t[0] = ~t[0]; t[1] = ~t[1]; t[2] = ~t[2]; t[3] = ~t[3]; t[4] = ~t[4];
	t[0] &= x[1]; t[1] &= x[2]; t[2] &= x[3]; t[3] &= x[4]; t[4] &= x[0];
	x[0] ^= t[1]; x[1] ^= t[2]; x[2] ^= t[3]; x[3] ^= t[4]; x[4] ^= t[0];
	x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] = ~x[2];

    x[0] = x[0] ^ROTR(x[0], 19) ^ ROTR (x[0], 28);
    x[1] = x[1] ^ROTR(x[1], 61) ^ ROTR (x[1], 39);
    x[2] = x[2] ^ROTR(x[2], 1) ^ ROTR (x[2], 6);
    x[3] = x[3] ^ROTR(x[3], 10) ^ ROTR (x[3], 17);
    x[4] = x[4] ^ROTR(x[4], 7) ^ ROTR (x[4], 41);
}
void initialization(uint64_t x[5], uint64_t IV,uint64_t key[2],uint64_t nonce[2]){
    x[0] = IV;
    x[1] = key[0];
    x[2] = key[1];
    x[3] = nonce[0];
    x[4] = nonce[1];
    print_state(x);
    for(int i = 0; i < loopNumber; i++){
        p(x, i, loopNumber);
    }
    x[3] ^= key[0];
    x[4] ^= key[1];
}
void ascon_encryption(uint64_t x[5], unsigned char plaintext[], uint64_t ciphertext[], int blocks){
    for(int i = 0; i < blocks; i++)
    {
        x[0] ^= plaintext[2*i];
        x[1] ^= plaintext[2*i + 1];
        ciphertext[2*i] = x[0];
        ciphertext[2*i + 1] = x[1];
    }
}
void finalization(uint64_t x[5],uint64_t key[2], uint64_t tag[2]){
    x[2] ^= key[0];
    x[3] ^= key[1];
    for(int i = 0; i < loopNumber; i++){
        p(x, i, loopNumber);
    }
    tag[0] = x[3] ^ key[0];
    tag[1] = x[4] ^ key[1];
}

// Performans Metrikleri için Sabitler
#define POWER_IN_UW 5000000 // 5W = 5,000,000 micro-watt, Apple M1 için 5-15W ortalama değere
#define CLOCK_SPEED_HZ 2800000000 // 2.8GHz (varsayım olarak Apple M1 için Cycles Per Second)

unsigned long long num_blocks = 0;

// Donanım ve yazılım frekansları
#define HARDWARE_FREQ_HZ 100000 // 100 kHz
#define SOFTWARE_FREQ_HZ 4000000 // 4 MHz



// Enerji hesaplama fonksiyonu (μJ)
double calculate_energy(unsigned char *plaintext, double cycles_per_block, double latency_seconds, int block_size_bits) {
    double power_in_uW = POWER_IN_UW;  // 5W = 5,000,000 μW (Apple M1 varsayımsal değer)
    num_blocks = (strlen((char *)plaintext) + block_size_bits - 1) / block_size_bits;
    double energy = ((cycles_per_block * num_blocks) * power_in_uW) / block_size_bits;
    return energy;  // μJ cinsinden
}

// Throughput hesaplama fonksiyonu (bits per second)
double calculate_throughput(int num_blocks, int block_size_bits, double time_taken_sec) {
    // İşlenen veri miktarı (bit cinsinden)
    int data_processed_bits = num_blocks * block_size_bits;
    
    // Donanım verimliliği hesapla (bits per second)
    double hardware_throughput = (data_processed_bits / time_taken_sec) * HARDWARE_FREQ_HZ;
    
    // Yazılım verimliliği hesapla (bits per second)
    double software_throughput = (data_processed_bits / time_taken_sec) * SOFTWARE_FREQ_HZ;
    
    // Sonuçları yazdır
    printf("Hardware Throughput (bits per second): %.2f\n", hardware_throughput);
    printf("Software Throughput (bits per second): %.2f\n", software_throughput);
    return software_throughput;

}

// Yazılım verimliliği hesaplama fonksiyonu
double calculate_efficiency(double throughput, double code_size_kge) {
    return throughput / code_size_kge;  // Kbps / kGE
}
double get_executable_code_size_kge(const char *executable_file) {
    struct stat statbuf;

    // Dosya boyutunu almak için stat fonksiyonunu kullanıyoruz
    if (stat(executable_file, &statbuf) == 0) {
        return statbuf.st_size; // Dosyanın boyutunu byte cinsinden döndürüyoruz
    } else {
        perror("Dosya bulunamadı");
        return -1;
    }

    // Boyutu byte cinsinden al ve kilobit cinsine çevir (1 byte = 8 bit, 1 kilobit = 1024 bits)
    double code_size_kge = (statbuf.st_size * 8) / 1024.0; // Kilo-gate equivalent (kGE) cinsinden
    return code_size_kge;
}

int main(int argc, char *argv[]) {
    uint64_t x[5] = {0};
    uint64_t IV = 0x00001000808c0001;
    uint64_t key[2] = {0};
    uint64_t nonce[2] = {0};
    unsigned char plaintext[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    uint64_t ciphertext[4] = {0};
    uint64_t tag[2] = {0};

    //unsigned char plaintext[] = "Hello, this is a test message!";
    int plaintext_len = strlen((char *)plaintext);

    // Performans metriklerini ölçmek için gerekli parametreler
    double cycles_per_block = 1000000;  // Örnek olarak birim başına 1M döngü (bu değer ölçülmelidir)
    int block_size_bits = 128;          // ASCON için blok boyutu 128 bit
    // Çalıştırılabilir dosyanın yolunu argv[0] üzerinden alıyoruz
    char *executable_file = argv[0];
    double code_size_kge = get_executable_code_size_kge(executable_file);          // Varsayım olarak 50 kGE

    // ASCON şifreleme işlemi
    //print_state(x);
    initialization(x, IV, key, nonce);
    //print_state(x);
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    ascon_encryption(x, plaintext, ciphertext, sizeof(plaintext) / 16);
    clock_gettime(CLOCK_MONOTONIC, &end);
    double latency = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1.0e9;

    int ciphertext_len = strlen((char *)ciphertext);
    printf("Ciphertext (hex):\n");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02llx ", ciphertext[i]);
    }
    printf("\n");

    // Performans metriklerini hesapla
    double cpu_time_used = latency / CLOCKS_PER_SEC;
    // Döngü sayısını hesaplamak için saniyeyi işlemci hızına çevir
    cycles_per_block = cpu_time_used * CLOCK_SPEED_HZ;
    double energy = calculate_energy(plaintext, cycles_per_block, latency, block_size_bits); // Enerji hesaplama
    num_blocks = (strlen((char *)plaintext) + block_size_bits - 1) / block_size_bits;
    double throughput = calculate_throughput(num_blocks, block_size_bits, latency); // Throughput hesaplama
    
    double efficiency = calculate_efficiency(throughput, code_size_kge); // Yazılım verimliliği hesaplama

    // Sonuçları ekrana yazdır
    printf("Performance Metrics:\n");
    printf("Latency (seconds): %.10f\n", latency);
    printf("Energy Consumption (μJ): %.10f\n", energy);
    printf("Throughput (bits/sec): %.10f\n", throughput);
    printf("Efficiency (Kbps/kGE): %.10f\n", efficiency);

    return 0;
}
