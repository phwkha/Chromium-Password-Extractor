# Browser Password Recovery Tool (C++)

Đây là một công cụ viết bằng C++ dành cho hệ điều hành Windows, có khả năng tự động tìm kiếm và giải mã các thông tin đăng nhập (URL, Username, Password) đã được lưu trên các trình duyệt sử dụng nhân Chromium.

## 🚀 Tính năng nổi bật

- Hỗ trợ giải mã mật khẩu đã lưu từ các trình duyệt phổ biến:
  - **Google Chrome**
  - **Microsoft Edge**
  - **Cốc Cốc**
  - **Brave Browser**
- **Quét toàn bộ Profile:** Tự động phát hiện và quét tất cả các profile (ví dụ: `Default`, `Profile 1`, `Profile 2`,...) của từng trình duyệt để không bỏ sót dữ liệu.
- Tự động tìm kiếm file `Local State` để trích xuất và giải mã **Master Key** (thông qua DPAPI - *CryptUnprotectData*).
- Giải mã chuẩn AES-GCM (thông qua *BCrypt*) đối với các mật khẩu được lưu trữ trong cơ sở dữ liệu SQLite (`Login Data`).

## 🛠 Yêu cầu hệ thống và môi trường

- **Hệ điều hành:** Windows (sử dụng các thư viện Windows API đặc thù như `windows.h`, `dpapi.h`, `shlobj.h`, `bcrypt.h`).
- **Ngôn ngữ:** C++ (C++11 hoặc mới hơn).
- **IDE đề xuất:** Visual Studio (Project đính kèm file `.sln` và `.vcxproj`).

## 📦 Cấu trúc mã nguồn

- `ChromiumPassExtractor/ChromiumPassExtractor.cpp`: Chứa mã nguồn chính của ứng dụng (Logic giải mã Base64, AES-GCM, đọc Local State và SQLite).
- `ChromiumPassExtractor/json.hpp`: Thư viện [nlohmann/json](https://github.com/nlohmann/json) dùng để parse file JSON `Local State`.
- `ChromiumPassExtractor/sqlite3.c` & `ChromiumPassExtractor/sqlite3.h`: Mã nguồn thư viện [SQLite](https://www.sqlite.org/) hỗ trợ truy vấn file cơ sở dữ liệu `Login Data`.
- `ChromiumPassExtractor.sln`: File Solution của Visual Studio.

## ⚙️ Hướng dẫn cài đặt và sử dụng

1. **Mở dự án:** Double-click vào file `ChromiumPassExtractor.sln` để mở project bằng Visual Studio.
2. **Biên dịch (Build):** 
   - Chọn cấu hình Build là `Release` hoặc `Debug`.
   - Bấm `Ctrl + Shift + B` để build toàn bộ solution.
3. **Chạy chương trình:** 
   - Chạy file thực thi (`.exe`) vừa được tạo ra.
   - Tool sẽ ngay lập tức tìm kiếm các trình duyệt hiện có trên máy tính của bạn, truy xuất file `Local State`, trích xuất `Master Key` và lần lượt giải mã các bản ghi đăng nhập ở tất cả các Profile. Kết quả sẽ được in trực tiếp ra màn hình console.

## ⚠️ Tuyên bố miễn trừ trách nhiệm (Disclaimer)

- Công cụ này được tạo ra **HOÀN TOÀN NHẰM MỤC ĐÍCH GIÁO DỤC, NGHIÊN CỨU BẢO MẬT (Security Research)** và hỗ trợ người dùng phục hồi lại các mật khẩu cá nhân bị quên.
- **NGHIÊM CẤM** sử dụng công cụ này vào các hành vi phi pháp, xâm phạm quyền riêng tư, đánh cắp dữ liệu của người khác hoặc phát tán mã độc. 
- Tác giả không chịu bất kỳ trách nhiệm pháp lý nào đối với những hành vi lạm dụng, vi phạm pháp luật từ phía người sử dụng.

---
*Developed with C++ and Windows Cryptography API.*
