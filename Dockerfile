# ---- ขั้นสร้าง (build) ----
FROM golang:alpine AS build
# GOTOOLCHAIN=auto: ถ้า go.mod ต้องการ Go เวอร์ชันใหม่กว่า ให้ดาวน์โหลดอัตโนมัติ
ENV GOTOOLCHAIN=auto CGO_ENABLED=0
WORKDIR /src
COPY . .
# ดึง library ที่ใช้ให้เองตอน build (ไม่ต้องมีเครื่อง/ไม่ต้องอัปโหลด go.sum)
RUN if [ ! -f go.mod ]; then go mod init digital-market; fi \
 && go mod tidy \
 && go build -trimpath -ldflags="-s -w" -o /app .

# ---- ขั้นรัน (เล็กและเบา) ----
FROM alpine:latest
# ca-certificates จำเป็น: ใช้ตรวจใบรับรอง TLS ตอนต่อ TiDB Cloud
RUN apk add --no-cache ca-certificates
ENV TZ=Asia/Bangkok
COPY --from=build /app /app
EXPOSE 10000
CMD ["/app"]
