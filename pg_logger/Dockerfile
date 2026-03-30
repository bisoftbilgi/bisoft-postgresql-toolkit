# --- AŞAMA 1: Derleme ---
FROM rust:1.75-slim AS builder

WORKDIR /usr/src/app

# Bağımlılıkları önbelleğe almak için hile:
# Sadece Cargo dosyalarını kopyalayıp boş bir proje derliyoruz.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -f target/release/deps/pg_rust_logger*

# Şimdi gerçek kodu kopyalayıp asıl derlemeyi yapıyoruz
COPY . .
RUN cargo build --release

# --- AŞAMA 2: Çalıştırma ---
FROM debian:bookworm-slim

# Gerekli sistem kütüphanelerini ekleyelim
RUN apt-get update && apt-get install -y ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Derlenen dosyayı kopyala
COPY --from=builder /usr/src/app/target/release/pg_rust_logger .

# Gerekli klasörleri oluştur (Bağlanacak volumelar için hazırlık)
RUN mkdir -p /app/sincedb /app/output /var/log/postgresql

# Uygulamayı çalıştır
CMD ["./pg_rust_logger"]