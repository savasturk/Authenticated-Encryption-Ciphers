#include <openssl/evp.h>
#include <openssl/aes.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "ascon.h"  // ASCON kütüphanesinin doğru versiyonunu dahil edin


#define KEY_SIZE 32  // ChaCha20-Poly1305 için 32 byte anahtar
#define IV_SIZE 12   // ChaCha20-Poly1305 için standart IV boyutu
#define TAG_SIZE 16  // ChaCha20-Poly1305 kimlik doğrulama etiketi boyutu

// Performans Metrikleri için Sabitler
#define POWER_IN_UW 5000000 // 5W = 5,000,000 micro-watt, Apple M1 için 5-15W ortalama değere
#define CLOCK_SPEED_HZ 2800000000 // 2.8GHz (varsayım olarak Apple M1 için Cycles Per Second)

unsigned long long num_blocks = 0;

// Donanım ve yazılım frekansları
#define HARDWARE_FREQ_HZ 100000 // 100 kHz
#define SOFTWARE_FREQ_HZ 4000000 // 4 MHz

// Gecikme (Latency) hesaplamak için fonksiyon
double get_latency_in_seconds() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Bekleme süresi veya şifreleme işlemi
    usleep(1000); // 1ms kadar bekletiyoruz (örnek olarak)

    clock_gettime(CLOCK_MONOTONIC, &end);
    double latency = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1.0e9;
    return latency;  // saniye cinsinden
}

// ChaCha20-Poly1305 şifreleme fonksiyonu
int chacha20_poly1305_encrypt(const unsigned char *plaintext, int plaintext_len,
                              const unsigned char *key, const unsigned char *iv,
                              unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // EVP_CIPHER_CTX yapısını oluştur
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("EVP_CIPHER_CTX_new failed");
        return -1;
    }

    // Şifreleme başlat
    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)) {
        perror("EVP_EncryptInit_ex failed");
        return -1;
    }

    // Anahtar ve IV ayarla
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        perror("EVP_EncryptInit_ex failed");
        return -1;
    }

    // Şifreli veriyi hesapla
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        perror("EVP_EncryptUpdate failed");
        return -1;
    }
    ciphertext_len = len;

    // Kimlik doğrulama etiketini al
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len)) {
        perror("EVP_EncryptFinal_ex failed");
        return -1;
    }
    ciphertext_len += len;

    // Kimlik doğrulama etiketini al
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag)) {
        perror("EVP_CIPHER_CTX_ctrl failed");
        return -1;
    }

    // Belleği temizle
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// ChaCha20-Poly1305 deşifreleme fonksiyonu
int chacha20_poly1305_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                              const unsigned char *key, const unsigned char *iv,
                              const unsigned char *tag, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    // EVP_CIPHER_CTX yapısını oluştur
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("EVP_CIPHER_CTX_new failed");
        return -1;
    }

    // Şifre çözme başlat
    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)) {
        perror("EVP_DecryptInit_ex failed");
        return -1;
    }

    // Anahtar ve IV ayarla
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        perror("EVP_DecryptInit_ex failed");
        return -1;
    }

    // Şifreli veriyi deşifre et
    ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    if (ret <= 0) {
        perror("EVP_DecryptUpdate failed");
        return -1;
    }
    plaintext_len = len;

    // Kimlik doğrulama etiketini doğrula
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, (void *)tag)) {
        perror("EVP_CIPHER_CTX_ctrl failed");
        return -1;
    }

    // Şifre çözme sonlandırma
    ret = EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len);
    if (ret > 0) {
        plaintext_len += len;
    } else {
        perror("Decryption failed. Tag verification failed");
        return -1;
    }

    // Belleği temizle
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
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

// Verilerin uyuşup uyuşmadığını kontrol etme
int verify_data(const unsigned char *plaintext, const unsigned char *decrypted, int len) {
    if (memcmp(plaintext, decrypted, len) == 0) {
        printf("Şifrelenmiş ve deşifrelenmiş veriler uyuşuyor.\n");
        return 1; // Uyuşuyor
    } else {
        printf("Şifrelenmiş ve deşifrelenmiş veriler uyuşmuyor.\n");
        return 0; // Uyuşmuyor
    }
}

int main(int argc, char *argv[]) {
    //unsigned char key[KEY_SIZE] = {0x00}; // Chacha20-128 key
    unsigned char key[KEY_SIZE] = "0123456789abcdef"; // Chacha20-128 key
    unsigned char iv[IV_SIZE] = {0x00};  // GCM IV, genellikle 12 byte
    unsigned char tag[TAG_SIZE];
    unsigned char plaintext[] = "Hello, this is a test message!";
    int plaintext_len = strlen((char *)plaintext);
    unsigned char ciphertext[1024];

    // Performans metriklerini ölçmek için gerekli parametreler
    double cycles_per_block = 1000000;  // Örnek olarak birim başına 1M döngü (bu değer ölçülmelidir)
    int block_size_bits = 128;          // AES-128 için blok boyutu 128 bit
    // Çalıştırılabilir dosyanın yolunu argv[0] üzerinden alıyoruz
    char *executable_file = argv[0];
    double code_size_kge = get_executable_code_size_kge(executable_file);          // Varsayım olarak 50 kGE

    // AES şifreleme işlemi
    int ciphertext_len = chacha20_poly1305_encrypt(plaintext, plaintext_len, key, iv, ciphertext, tag);


    printf("Ciphertext (hex):\n");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");
     unsigned char decrypted[1024];
    
    // Deşifreleme işlemi
    int decrypted_len = chacha20_poly1305_decrypt(ciphertext, ciphertext_len, key, iv, tag, decrypted);

    if (decrypted_len == -1) {
        printf("Deşifreleme başarısız.\n");
        return -1;
    }

    printf("Deşifrelenmiş veri başarıyla oluşturuldu.\n");

    // Verilerin uyuşup uyuşmadığını kontrol et
    if (verify_data(plaintext, decrypted, plaintext_len)) {
        printf("Veriler doğru bir şekilde deşifre edildi.\n");
    } else {
        printf("Verilerde bir uyuşmazlık tespit edildi.\n");
    }


    // Performans metriklerini hesapla
    double latency = get_latency_in_seconds(); // Latency ölçümü
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
